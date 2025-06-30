import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// Define the environment variables, especially the secret for Google Auth
 interface Env {
   GOOGLE_SERVICE_ACCOUNT_JSON: string;
 }

// Helper function to get a Google Auth Access Token from a service account
// This uses a lightweight, zero-dependency JWT implementation suitable for Cloudflare Workers.
async function getGoogleAuthToken(serviceAccountJson: string): Promise<string> {
    const serviceAccount = JSON.parse(serviceAccountJson);
    const scope = "https://www.googleapis.com/auth/analytics.readonly";
    const jwtHeader = {
        alg: "RS256",
        typ: "JWT",
    };

    const now = Math.floor(Date.now() / 1000);
    const expiry = now + 3600; // 1 hour expiration

    const jwtClaimSet = {
        iss: serviceAccount.client_email,
        scope: scope,
        aud: "https://oauth2.googleapis.com/token",
        exp: expiry,
        iat: now,
    };

    const encodedHeader = btoa(JSON.stringify(jwtHeader)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const encodedClaimSet = btoa(JSON.stringify(jwtClaimSet)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

    const signingInput = `${encodedHeader}.${encodedClaimSet}`;

    // Import the private key to sign the JWT
    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        (s => new Uint8Array(Array.prototype.map.call(atob(s), (c) => c.charCodeAt(0))))(serviceAccount.private_key.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\n/g, '')),
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["sign"]
    );

    const signature = await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        privateKey,
        new TextEncoder().encode(signingInput)
    );

    const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const jwt = `${signingInput}.${encodedSignature}`;

    // Exchange the signed JWT for an access token
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
    });

    if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        throw new Error(`Failed to fetch Google Auth token: ${errorText}`);
    }

    const tokenData = await tokenResponse.json();
    return tokenData.access_token;
}


// Define our GA4 Reporting MCP Agent
export class MyGA4Reporter extends McpAgent<Env> {
  server = new McpServer({
    name: "GA4 Report Connector",
    version: "1.0.0",
  });

  async init() {
    this.server.tool(
      "run_ga4_report",
      // Define the input schema using Zod for validation
      {
        propertyId: z.string().describe("Your Google Analytics 4 Property ID (e.g., '123456789')"),
        dimensions: z.array(z.string()).describe("List of dimension names (e.g., ['city', 'date'])"),
        metrics: z.array(z.string()).describe("List of metric names (e.g., ['activeUsers', 'sessions'])"),
        dateRanges: z.array(
            z.object({
                startDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Date must be in YYYY-MM-DD format"),
                endDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Date must be in YYYY-MM-DD format"),
            })
        ).describe("Array of date ranges for the report"),
      },
      // The async handler that executes when the tool is called
      async (params, { env }) => {
        try {
          // 1. Get the access token using the service account secret

          const accessToken = await getGoogleAuthToken("env.GOOGLE_SERVICE_ACCOUNT_JSON");
          
          // 2. Construct the request body for the GA4 Data API
          const requestBody = {
            dimensions: params.dimensions.map(name => ({ name })),
            metrics: params.metrics.map(name => ({ name })),
            dateRanges: params.dateRanges,
          };

          const apiUrl = `https://analyticsdata.googleapis.com/v1beta/properties/${params.propertyId}:runReport`;

          // 3. Make the API call to Google Analytics
          const reportResponse = await fetch(apiUrl, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${accessToken}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody),
          });

          if (!reportResponse.ok) {
            const errorBody = await reportResponse.json();
            const errorMessage = errorBody.error?.message || "An unknown error occurred.";
            return {
              content: [{ type: "text", text: `GA4 API Error: ${errorMessage}` }],
              isError: true,
            };
          }

          const report = await reportResponse.json();

          // 4. Format the JSON response into a human-readable Markdown table
          if (!report.rows || report.rows.length === 0) {
              return { content: [{ type: "text", text: "The report returned no data." }] };
          }

          const dimensionHeaders = report.dimensionHeaders.map(h => h.name);
          const metricHeaders = report.metricHeaders.map(h => h.name);
          const allHeaders = [...dimensionHeaders, ...metricHeaders];

          let markdownTable = `| ${allHeaders.join(' | ')} |\n`;
          markdownTable += `|${allHeaders.map(() => '---').join('|')}|\n`;

          for (const row of report.rows) {
              const dimValues = row.dimensionValues.map(v => v.value);
              const metValues = row.metricValues.map(v => v.value);
              const allValues = [...dimValues, ...metValues];
              markdownTable += `| ${allValues.join(' | ')} |\n`;
          }

          return { content: [{ type: "text", text: markdownTable }] };

        } catch (error) {
          console.error("Error in run_ga4_report tool:", error);
          return {
            content: [{ type: "text", text: `An internal error occurred: ${error.message}` }],
            isError: true,
          };
        }
      }
    );
  }
}

// Standard Cloudflare Worker fetch handler
export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    if (url.pathname === "/sse" || url.pathname === "/sse/message") {
      return MyGA4Reporter.serveSSE("/sse").fetch(request, env, ctx);
    }

    if (url.pathname === "/mcp") {
      return MyGA4Reporter.serve("/mcp").fetch(request, env, ctx);
    }

    return new Response("Not found. Use the /mcp or /sse endpoint.", { status: 404 });
  },
};
