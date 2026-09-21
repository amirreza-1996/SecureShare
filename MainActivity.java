package com.secureshare.app;

import android.Manifest;
import android.app.Activity;
import android.content.*;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.*;
import android.provider.OpenableColumns;
import android.database.Cursor;
import android.view.*;
import android.widget.*;
import java.io.*;

public final class MainActivity extends Activity {
    private static final int PICK_FILE = 5001;
    private EditText server,email,smtp,imap,user,pass,secret,poll;
    private TextView status,folder;
    private AppConfig cfg;

    @Override public void onCreate(Bundle b){super.onCreate(b);getWindow().getDecorView().setLayoutDirection(View.LAYOUT_DIRECTION_RTL);cfg=AppConfig.load(this);build();if(Build.VERSION.SDK_INT>=33&&checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED)requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},44);}
    private EditText input(LinearLayout root,String label,String value,boolean password){TextView l=new TextView(this);l.setText(label);l.setPadding(0,12,0,4);root.addView(l);EditText e=new EditText(this);e.setText(value);e.setSingleLine(true);if(password)e.setInputType(0x00000081);root.addView(e,new LinearLayout.LayoutParams(-1,-2));return e;}
    private Button button(String text){Button b=new Button(this);b.setText(text);return b;}
    private void build(){ScrollView sv=new ScrollView(this);LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(28,24,28,24);sv.addView(root);TextView title=new TextView(this);title.setText("SecureShare");title.setTextSize(28);root.addView(title);status=new TextView(this);status.setText("آماده");status.setPadding(0,14,0,14);root.addView(status);folder=new TextView(this);folder.setText("پوشه گوشی: در حال آماده‌سازی...");root.addView(folder);
        LinearLayout actions=new LinearLayout(this);actions.setOrientation(LinearLayout.HORIZONTAL);Button syncB=button("Sync الآن");Button importB=button("افزودن فایل");Button testB=button("تست اتصال");actions.addView(syncB);actions.addView(importB);actions.addView(testB);root.addView(actions);
        server=input(root,"Mail Server",cfg.server,false);email=input(root,"ایمیل",cfg.email,false);smtp=input(root,"SMTP Port",String.valueOf(cfg.smtpPort),false);imap=input(root,"IMAP Port",String.valueOf(cfg.imapPort),false);user=input(root,"نام کاربری",cfg.username,false);pass=input(root,"رمز ایمیل",cfg.password,true);secret=input(root,"رمز مشترک رمزگذاری",cfg.sharedSecret,true);poll=input(root,"فاصله Sync (ثانیه)",String.valueOf(cfg.pollSeconds),false);
        Button saveB=button("ذخیره و فعال‌کردن Sync پس‌زمینه");root.addView(saveB,new LinearLayout.LayoutParams(-1,-2));TextView note=new TextView(this);note.setText("محتوا و نام فایل‌ها پیش از ارسال رمزگذاری می‌شوند. اتصال حساب ایمیل ممکن است در لاگ Mail Server قابل مشاهده باشد.");note.setPadding(0,14,0,20);root.addView(note);setContentView(sv);
        try{folder.setText("پوشه گوشی: "+new SyncEngine(this,cfg).folder().getAbsolutePath());}catch(Exception e){folder.setText("خطای پوشه: "+e.getMessage());}
        saveB.setOnClickListener(v->saveAndStart());syncB.setOnClickListener(v->syncNow());testB.setOnClickListener(v->testConn());importB.setOnClickListener(v->{Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);i.setType("*/*");i.addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(i,PICK_FILE);});
    }
    private AppConfig readForm(){AppConfig c=cfg;c.server=server.getText().toString().trim();c.email=email.getText().toString().trim();c.smtpPort=parseInt(smtp.getText().toString(),465);c.imapPort=parseInt(imap.getText().toString(),993);c.username=user.getText().toString().trim();c.password=pass.getText().toString();c.sharedSecret=secret.getText().toString();c.pollSeconds=Math.max(10,parseInt(poll.getText().toString(),30));return c;}
    private int parseInt(String s,int d){try{return Integer.parseInt(s.trim());}catch(Exception e){return d;}}
    private void saveAndStart(){try{cfg=readForm();cfg.save(this);Intent i=new Intent(this,SyncService.class);if(Build.VERSION.SDK_INT>=26)startForegroundService(i);else startService(i);status.setText("تنظیمات ذخیره شد و Sync فعال شد");}catch(Exception e){status.setText("خطا: "+e.getMessage());}}
    private void syncNow(){status.setText("در حال Sync...");new Thread(()->{try{AppConfig c=readForm();new SyncEngine(this,c).sync();runOnUiThread(()->status.setText("همگام‌سازی انجام شد"));}catch(Exception e){runOnUiThread(()->status.setText("خطا: "+e.getMessage()));}}).start();}
    private void testConn(){status.setText("در حال تست SMTP/IMAP...");new Thread(()->{try{MailTransport.test(readForm());runOnUiThread(()->status.setText("SMTP و IMAP موفق"));}catch(Exception e){runOnUiThread(()->status.setText("خطا: "+e.getMessage()));}}).start();}
    private String displayName(Uri u){try(Cursor c=getContentResolver().query(u,null,null,null,null)){if(c!=null&&c.moveToFirst()){int i=c.getColumnIndex(OpenableColumns.DISPLAY_NAME);if(i>=0)return c.getString(i);}}return "file.bin";}
    @Override protected void onActivityResult(int req,int res,Intent data){super.onActivityResult(req,res,data);if(req==PICK_FILE&&res==RESULT_OK&&data!=null&&data.getData()!=null){Uri u=data.getData();new Thread(()->{try{SyncEngine e=new SyncEngine(this,readForm());File dst=new File(e.folder(),displayName(u));try(InputStream in=getContentResolver().openInputStream(u);OutputStream out=new FileOutputStream(dst)){byte[] b=new byte[65536];int n;while((n=in.read(b))>0)out.write(b,0,n);}e.sync();runOnUiThread(()->status.setText("فایل اضافه و Sync شد: "+dst.getName()));}catch(Exception ex){runOnUiThread(()->status.setText("خطا: "+ex.getMessage()));}}).start();}}
}
