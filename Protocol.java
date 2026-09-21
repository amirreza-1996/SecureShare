package com.secureshare.app;

import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public final class Protocol {
    public static final class Header {
        public int version = 1;
        public String op = "";
        public String path = "";
        public String hash = "";
        public long modified = 0;
        public long size = 0;
        public String sender = "";
        public String fileId = "";
        public int chunkIndex = 0;
        public int chunkCount = 1;
    }

    public static byte[] pack(Header h, byte[] data) throws Exception {
        JSONObject j = new JSONObject();
        j.put("v", h.version); j.put("op", h.op); j.put("path", h.path); j.put("hash", h.hash);
        j.put("modified", h.modified); j.put("size", h.size); j.put("sender", h.sender); j.put("fileId", h.fileId);
        j.put("chunkIndex", h.chunkIndex); j.put("chunkCount", h.chunkCount);
        byte[] hb = j.toString().getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{'S','S','P','1'});
        out.write(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(hb.length).array());
        out.write(hb); out.write(data);
        return out.toByteArray();
    }

    public static final class Parsed { public Header header; public byte[] data; }
    public static Parsed unpack(byte[] p) throws Exception {
        if (p.length < 8 || p[0] != 'S' || p[1] != 'S' || p[2] != 'P' || p[3] != '1') throw new Exception("Invalid packet");
        int n = ByteBuffer.wrap(p, 4, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        if (n < 2 || 8 + n > p.length) throw new Exception("Invalid packet header");
        JSONObject j = new JSONObject(new String(p, 8, n, StandardCharsets.UTF_8));
        Header h = new Header();
        h.version = j.optInt("v",1); h.op=j.optString("op",""); h.path=j.optString("path",""); h.hash=j.optString("hash","");
        h.modified=j.optLong("modified",0); h.size=j.optLong("size",0); h.sender=j.optString("sender",""); h.fileId=j.optString("fileId","");
        h.chunkIndex=j.optInt("chunkIndex",0); h.chunkCount=j.optInt("chunkCount",1);
        byte[] data = new byte[p.length - 8 - n]; System.arraycopy(p, 8+n, data, 0, data.length);
        Parsed r = new Parsed(); r.header=h; r.data=data; return r;
    }
}
