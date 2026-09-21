package com.secureshare.app;

import android.util.Base64;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import javax.net.ssl.*;

public final class MailTransport {
    private static final SecureRandom RNG = new SecureRandom();
    private static String rnd(int n){ byte[] b=new byte[(n+1)/2];RNG.nextBytes(b);StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02x",x));return s.substring(0,n); }
    private static String readLine(BufferedReader r) throws IOException { String s=r.readLine(); if(s==null)throw new EOFException(); return s; }
    private static void expect(BufferedReader r, int code) throws IOException {
        String line=readLine(r); if(line.length()<3||Integer.parseInt(line.substring(0,3))!=code)throw new IOException("SMTP: "+line);
        while(line.length()>3&&line.charAt(3)=='-') line=readLine(r);
    }
    private static void sendLine(BufferedWriter w,String s)throws IOException{w.write(s);w.write("\r\n");w.flush();}

    public static void test(AppConfig c) throws Exception { smtpAuthOnly(c); Imap im=new Imap(c); im.close(); }
    private static void smtpAuthOnly(AppConfig c)throws Exception{
        SSLSocketFactory f=(SSLSocketFactory)SSLSocketFactory.getDefault(); try(SSLSocket s=(SSLSocket)f.createSocket(c.server,c.smtpPort)){
            s.startHandshake(); BufferedReader r=new BufferedReader(new InputStreamReader(s.getInputStream(),StandardCharsets.US_ASCII));BufferedWriter w=new BufferedWriter(new OutputStreamWriter(s.getOutputStream(),StandardCharsets.US_ASCII));expect(r,220);sendLine(w,"EHLO secureshare");expect(r,250);sendLine(w,"AUTH LOGIN");expect(r,334);sendLine(w,Base64.encodeToString(c.username.getBytes(StandardCharsets.UTF_8),Base64.NO_WRAP));expect(r,334);sendLine(w,Base64.encodeToString(c.password.getBytes(StandardCharsets.UTF_8),Base64.NO_WRAP));expect(r,235);sendLine(w,"QUIT");
        }
    }

    public static void send(AppConfig c, byte[] payload) throws Exception {
        SSLSocketFactory f=(SSLSocketFactory)SSLSocketFactory.getDefault(); try(SSLSocket s=(SSLSocket)f.createSocket(c.server,c.smtpPort)){
            s.startHandshake(); BufferedReader r=new BufferedReader(new InputStreamReader(s.getInputStream(),StandardCharsets.US_ASCII));BufferedWriter w=new BufferedWriter(new OutputStreamWriter(s.getOutputStream(),StandardCharsets.US_ASCII));expect(r,220);sendLine(w,"EHLO secureshare");expect(r,250);sendLine(w,"AUTH LOGIN");expect(r,334);sendLine(w,Base64.encodeToString(c.username.getBytes(StandardCharsets.UTF_8),Base64.NO_WRAP));expect(r,334);sendLine(w,Base64.encodeToString(c.password.getBytes(StandardCharsets.UTF_8),Base64.NO_WRAP));expect(r,235);sendLine(w,"MAIL FROM:<"+c.email+">");expect(r,250);sendLine(w,"RCPT TO:<"+c.email+">");expect(r,250);sendLine(w,"DATA");expect(r,354);
            String boundary="ss-"+rnd(12);StringBuilder h=new StringBuilder();h.append("From: SecureShare <").append(c.email).append(">\r\nTo: ").append(c.email).append("\r\nSubject: SecureShare Sync\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"").append(boundary).append("\"\r\n\r\n");h.append("--").append(boundary).append("\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nEncrypted SecureShare payload.\r\n");h.append("--").append(boundary).append("\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"payload.bin\"\r\nContent-Transfer-Encoding: base64\r\n\r\n");w.write(h.toString());String b64=Base64.encodeToString(payload,Base64.NO_WRAP);for(int i=0;i<b64.length();i+=76){w.write(b64.substring(i,Math.min(i+76,b64.length())));w.write("\r\n");}w.write("--"+boundary+"--\r\n.\r\n");w.flush();expect(r,250);sendLine(w,"QUIT");
        }
    }

    public static final class Imap implements Closeable {
        private final SSLSocket socket; private final BufferedInputStream in; private final BufferedWriter out; private int tag=0;
        public Imap(AppConfig c)throws Exception{SSLSocketFactory f=(SSLSocketFactory)SSLSocketFactory.getDefault();socket=(SSLSocket)f.createSocket(c.server,c.imapPort);socket.startHandshake();in=new BufferedInputStream(socket.getInputStream());out=new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(),StandardCharsets.US_ASCII));readAsciiLine();cmd("LOGIN "+quote(c.username)+" "+quote(c.password));cmd("SELECT INBOX");}
        private static String quote(String s){return "\""+s.replace("\\","\\\\").replace("\"","\\\"")+"\"";}
        private String next(){tag++;return String.format(Locale.US,"A%04d",tag);} private String readAsciiLine()throws IOException{ByteArrayOutputStream b=new ByteArrayOutputStream();int x;while((x=in.read())!=-1){b.write(x);if(x=='\n')break;}if(b.size()==0)throw new EOFException();return b.toString("US-ASCII");}
        private List<String> cmd(String c)throws Exception{String t=next();out.write(t+" "+c+"\r\n");out.flush();List<String> lines=new ArrayList<>();while(true){String l=readAsciiLine().trim();lines.add(l);if(l.startsWith(t+" ")){if(!l.toUpperCase(Locale.US).contains(" OK"))throw new IOException("IMAP: "+l);return lines;}}}
        public List<Integer> search()throws Exception{List<String> ls=cmd("SEARCH UNSEEN HEADER Subject \"SecureShare Sync\"");List<Integer> out=new ArrayList<>();for(String l:ls)if(l.startsWith("* SEARCH")){for(String p:l.substring(8).trim().split(" +"))if(!p.isEmpty())out.add(Integer.parseInt(p));}return out;}
        public byte[] fetch(int seq)throws Exception{String t=next();out.write(t+" FETCH "+seq+" BODY.PEEK[]\r\n");out.flush();byte[] lit=null;while(true){String l=readAsciiLine();String tr=l.trim();int a=tr.lastIndexOf('{'),b=tr.lastIndexOf('}');if(a>=0&&b==tr.length()-1){int n=Integer.parseInt(tr.substring(a+1,b));lit=new byte[n];int off=0;while(off<n){int k=in.read(lit,off,n-off);if(k<0)throw new EOFException();off+=k;}continue;}if(l.startsWith(t+" ")){if(!l.toUpperCase(Locale.US).contains(" OK"))throw new IOException("IMAP FETCH: "+l);return lit;}}}
        public void markSeen(int seq)throws Exception{cmd("STORE "+seq+" +FLAGS (\\Seen)");}
        public void close(){try{cmd("LOGOUT");}catch(Exception ignored){}try{socket.close();}catch(Exception ignored){}}
    }

    public static byte[] extractPayload(byte[] raw)throws Exception{
        String s=new String(raw,StandardCharsets.ISO_8859_1);int p=s.indexOf("filename=\"payload.bin\"");if(p<0)throw new IOException("payload not found");int start=s.indexOf("\r\n\r\n",p);if(start<0)throw new IOException("mime body not found");start+=4;int end=s.indexOf("\r\n--",start);if(end<0)throw new IOException("mime boundary not found");String b64=s.substring(start,end).replace("\r","").replace("\n","").trim();return Base64.decode(b64,Base64.DEFAULT);
    }
}
