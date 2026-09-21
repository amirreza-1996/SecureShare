package com.secureshare.app;

import android.content.Context;
import org.json.JSONObject;
import java.io.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.*;

public final class SyncEngine {
    private static final int CHUNK_SIZE = 5 * 1024 * 1024;
    private final Context ctx;
    private final AppConfig cfg;
    private final File root;
    private final File stateFile;
    private final JSONObject state;

    public SyncEngine(Context ctx, AppConfig cfg) throws Exception {
        this.ctx = ctx.getApplicationContext(); this.cfg = cfg;
        File base = ctx.getExternalFilesDir(null); if (base == null) base = ctx.getFilesDir();
        root = new File(base, "SecureShare"); if (!root.exists() && !root.mkdirs()) throw new IOException("Cannot create SecureShare folder");
        File meta = new File(root, ".secureshare"); if (!meta.exists()) meta.mkdirs(); stateFile = new File(meta, "state.json");
        state = loadState();
    }

    public File folder(){ return root; }
    private JSONObject loadState(){try{if(stateFile.exists())return new JSONObject(new String(Files.readAllBytes(stateFile.toPath()),"UTF-8"));}catch(Exception ignored){}return new JSONObject();}
    private void saveState(){try(FileOutputStream o=new FileOutputStream(stateFile)){o.write(state.toString().getBytes("UTF-8"));}catch(Exception ignored){}}
    private static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format(Locale.US,"%02x",x));return s.toString();}
    private static String hash(File f)throws Exception{MessageDigest d=MessageDigest.getInstance("SHA-256");try(InputStream in=new FileInputStream(f)){byte[] b=new byte[65536];int n;while((n=in.read(b))>0)d.update(b,0,n);}return hex(d.digest());}
    private static String randomId(){return UUID.randomUUID().toString().replace("-","");}
    private String rel(File f)throws Exception{String rp=root.getCanonicalPath();String fp=f.getCanonicalPath();if(!fp.startsWith(rp+File.separator))throw new IOException("Unsafe path");return fp.substring(rp.length()+1).replace(File.separatorChar,'/');}
    private File safeFile(String rel)throws Exception{if(rel.startsWith("/")||rel.contains(":")||rel.contains("../")||rel.equals(".."))throw new IOException("Unsafe path");File f=new File(root,rel.replace('/',File.separatorChar));String rp=root.getCanonicalPath();String fp=f.getCanonicalPath();if(!fp.startsWith(rp+File.separator))throw new IOException("Unsafe path");return f;}

    public synchronized void sync() throws Exception { pull(); push(); }
    private void walk(File dir,List<File> out){File[] fs=dir.listFiles();if(fs==null)return;for(File f:fs){if(f.getName().equals(".secureshare"))continue;if(f.isDirectory())walk(f,out);else out.add(f);}}
    private void push() throws Exception {
        List<File> files=new ArrayList<>();walk(root,files);Set<String> current=new HashSet<>();
        for(File f:files){String r=rel(f);current.add(r);String h=hash(f);JSONObject old=state.optJSONObject(r);if(old==null||!h.equals(old.optString("hash"))){sendPut(r,f,h);JSONObject n=new JSONObject();n.put("hash",h);n.put("modified",f.lastModified());n.put("size",f.length());state.put(r,n);saveState();}}
        List<String> deleted=new ArrayList<>();Iterator<String> it=state.keys();while(it.hasNext()){String r=it.next();if(!current.contains(r))deleted.add(r);}for(String r:deleted){sendDelete(r);state.remove(r);saveState();}
    }
    private void sendPut(String path,File f,String h)throws Exception{long size=f.length();int count=(int)Math.max(1,(size+CHUNK_SIZE-1)/CHUNK_SIZE);String id=randomId();try(InputStream in=new FileInputStream(f)){for(int i=0;i<count;i++){int want=(int)Math.min(CHUNK_SIZE,Math.max(0,size-(long)i*CHUNK_SIZE));byte[] data=new byte[want];int off=0;while(off<want){int n=in.read(data,off,want-off);if(n<0)throw new EOFException();off+=n;}Protocol.Header ph=new Protocol.Header();ph.op="put";ph.path=path;ph.hash=h;ph.modified=f.lastModified();ph.size=size;ph.sender=cfg.deviceId;ph.fileId=id;ph.chunkIndex=i;ph.chunkCount=count;byte[] enc=CryptoUtil.encrypt(cfg.sharedSecret,Protocol.pack(ph,data));MailTransport.send(cfg,enc);}}}
    private void sendDelete(String path)throws Exception{Protocol.Header ph=new Protocol.Header();ph.op="delete";ph.path=path;ph.sender=cfg.deviceId;ph.fileId=randomId();MailTransport.send(cfg,CryptoUtil.encrypt(cfg.sharedSecret,Protocol.pack(ph,new byte[0])));}

    private void pull() throws Exception {try(MailTransport.Imap im=new MailTransport.Imap(cfg)){for(int seq:im.search()){byte[] raw=im.fetch(seq);try{byte[] enc=MailTransport.extractPayload(raw);Protocol.Parsed p=Protocol.unpack(CryptoUtil.decrypt(cfg.sharedSecret,enc));if(!cfg.deviceId.equals(p.header.sender))apply(p.header,p.data);im.markSeen(seq);}catch(Exception ex){throw ex;}}}}
    private void apply(Protocol.Header h,byte[] data)throws Exception{File dest=safeFile(h.path);if(h.op.equals("delete")){JSONObject old=state.optJSONObject(h.path);if(old!=null&&dest.exists()){String cur=hash(dest);if(!cur.equals(old.optString("hash")))conflict(dest);}if(dest.exists())dest.delete();state.remove(h.path);saveState();return;}if(!h.op.equals("put"))return;File partDir=new File(new File(new File(root,".secureshare"),"chunks"),h.fileId);partDir.mkdirs();File part=new File(partDir,String.format(Locale.US,"%06d.part",h.chunkIndex));try(FileOutputStream o=new FileOutputStream(part)){o.write(data);}for(int i=0;i<h.chunkCount;i++)if(!new File(partDir,String.format(Locale.US,"%06d.part",i)).exists())return;if(dest.getParentFile()!=null)dest.getParentFile().mkdirs();File tmp=new File(dest.getPath()+".secureshare.tmp");try(OutputStream o=new FileOutputStream(tmp)){for(int i=0;i<h.chunkCount;i++){File q=new File(partDir,String.format(Locale.US,"%06d.part",i));try(InputStream in=new FileInputStream(q)){byte[] b=new byte[65536];int n;while((n=in.read(b))>0)o.write(b,0,n);}}}if(!hash(tmp).equals(h.hash)){tmp.delete();throw new IOException("Hash mismatch");}JSONObject old=state.optJSONObject(h.path);if(old!=null&&dest.exists()){String cur=hash(dest);if(!cur.equals(old.optString("hash"))&&!cur.equals(h.hash))conflict(dest);}if(dest.exists())dest.delete();if(!tmp.renameTo(dest))throw new IOException("Cannot replace file");if(h.modified>0)dest.setLastModified(h.modified);JSONObject n=new JSONObject();n.put("hash",h.hash);n.put("modified",h.modified);n.put("size",h.size);state.put(h.path,n);saveState();deleteTree(partDir);}
    private void conflict(File f)throws Exception{String name=f.getName();int dot=name.lastIndexOf('.');String base=dot>0?name.substring(0,dot):name;String ext=dot>0?name.substring(dot):"";File c=new File(f.getParentFile(),base+" (conflict "+System.currentTimeMillis()+")"+ext);try(InputStream in=new FileInputStream(f);OutputStream out=new FileOutputStream(c)){byte[] b=new byte[65536];int n;while((n=in.read(b))>0)out.write(b,0,n);}}
    private static void deleteTree(File f){if(f.isDirectory()){File[] a=f.listFiles();if(a!=null)for(File x:a)deleteTree(x);}f.delete();}
}
