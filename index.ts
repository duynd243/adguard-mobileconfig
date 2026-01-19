import { Hono } from "hono";
import { env } from "hono/adapter";
import { basicAuth } from "hono/basic-auth";

const app = new Hono();

// Template XML (.mobileconfig)
const TEMPLATE_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadUUID</key>
    <string>TEMPLATE-UUID</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadOrganization</key>
    <string>AdGuard</string>
    <key>PayloadIdentifier</key>
    <string>com.duy.adguard.doh</string>
    <key>PayloadDisplayName</key>
    <string>AdGuard DoH</string>
    <key>PayloadDescription</key>
    <string>AdGuard Home DoH - Nginx</string>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.duy.adguard.dns</string>
            <key>PayloadUUID</key>
            <string>5fd065c8-3b1b-4bfd-8fa8-2e593c12e3d2</string>
            <key>PayloadDisplayName</key>
            <string>AdGuard DoH</string>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>%BASE_PATH%/%MY_KEY%/dns-query/%CLIENT_ID%</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>`;

app.get(
  "/config/:client_id",
  basicAuth({
    username: "admin",
    verifyUser: (username, password, c) => {
      const { BASIC_AUTH_PASSWORD } = env<{ BASIC_AUTH_PASSWORD: string }>(c);
      return username === "admin" && password === BASIC_AUTH_PASSWORD;
    },
  }),
  (c) => {
    const client_id = c.req.param("client_id");
    const { MY_KEY, BASE_PATH } = env<{ MY_KEY: string; BASE_PATH: string }>(c);

    if (!client_id || !MY_KEY || !BASE_PATH) {
      return c.text("Missing parameters", 400);
    }

    const profileUUID = crypto.randomUUID();
    const configXML = TEMPLATE_XML.replace(
      /%BASE_PATH%/g,
      BASE_PATH.replace(/\/+$/, "")
    )
      .replace(/%MY_KEY%/g, MY_KEY)
      .replace(/%CLIENT_ID%/g, client_id)
      .replace("TEMPLATE-UUID", profileUUID);

    c.header("Content-Type", "application/x-apple-aspen-config");
    c.header(
      "Content-Disposition",
      `attachment; filename="Duy-AdGuard-DoH-${client_id}.mobileconfig"`
    );

    return c.body(configXML, 200);
  }
);

export default app;
