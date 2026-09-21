package com.secureshare.app;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.UUID;

public final class AppConfig {
    public String server = "mail.icatec.ir";
    public int smtpPort = 465;
    public int imapPort = 993;
    public String email = "";
    public String username = "";
    public String password = "";
    public String sharedSecret = "";
    public int pollSeconds = 30;
    public String deviceId = UUID.randomUUID().toString().replace("-", "");

    public static AppConfig load(Context ctx) {
        AppConfig c = new AppConfig();
        SharedPreferences p = ctx.getSharedPreferences("secureshare", Context.MODE_PRIVATE);
        c.server = p.getString("server", c.server);
        c.smtpPort = p.getInt("smtpPort", c.smtpPort);
        c.imapPort = p.getInt("imapPort", c.imapPort);
        c.email = p.getString("email", "");
        c.username = p.getString("username", "");
        c.pollSeconds = Math.max(10, p.getInt("pollSeconds", 30));
        c.deviceId = p.getString("deviceId", c.deviceId);
        try { c.password = SecretStore.get(ctx, "password"); } catch (Exception ignored) {}
        try { c.sharedSecret = SecretStore.get(ctx, "sharedSecret"); } catch (Exception ignored) {}
        return c;
    }

    public void save(Context ctx) throws Exception {
        ctx.getSharedPreferences("secureshare", Context.MODE_PRIVATE).edit()
                .putString("server", server)
                .putInt("smtpPort", smtpPort)
                .putInt("imapPort", imapPort)
                .putString("email", email)
                .putString("username", username)
                .putInt("pollSeconds", Math.max(10, pollSeconds))
                .putString("deviceId", deviceId)
                .apply();
        SecretStore.put(ctx, "password", password);
        SecretStore.put(ctx, "sharedSecret", sharedSecret);
    }

    public boolean ready() {
        return !server.isEmpty() && !email.isEmpty() && !username.isEmpty() && !password.isEmpty() && !sharedSecret.isEmpty();
    }
}
