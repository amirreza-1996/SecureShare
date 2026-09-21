package com.secureshare.app;

import android.app.*;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

public final class SyncService extends Service {
    private volatile boolean stop = false;
    @Override public void onCreate(){super.onCreate();String ch="secureshare_sync";if(Build.VERSION.SDK_INT>=26){NotificationChannel nc=new NotificationChannel(ch,"SecureShare Sync",NotificationManager.IMPORTANCE_LOW);getSystemService(NotificationManager.class).createNotificationChannel(nc);}Notification.Builder b=Build.VERSION.SDK_INT>=26?new Notification.Builder(this,ch):new Notification.Builder(this);b.setContentTitle("SecureShare").setContentText("همگام‌سازی فایل فعال است").setSmallIcon(android.R.drawable.stat_sys_upload_done);startForeground(1107,b.build());}
    @Override public int onStartCommand(Intent intent,int flags,int id){stop=false;new Thread(()->{while(!stop){try{AppConfig c=AppConfig.load(this);if(c.ready())new SyncEngine(this,c).sync();Thread.sleep(Math.max(10,c.pollSeconds)*1000L);}catch(Exception e){try{Thread.sleep(30000);}catch(InterruptedException ignored){}}}}).start();return START_STICKY;}
    @Override public void onDestroy(){stop=true;super.onDestroy();}
    @Override public IBinder onBind(Intent i){return null;}
}
