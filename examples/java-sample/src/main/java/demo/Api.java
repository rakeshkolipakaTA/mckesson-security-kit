package demo;

import java.io.*;
import java.security.MessageDigest;
import java.sql.*;

public class Api {
    static final String DB_PASSWORD = "Pa55w0rd-prod-db";                       // hardcoded password

    public ResultSet find(Connection c, String name) throws SQLException {
        Statement s = c.createStatement();
        return s.executeQuery("SELECT * FROM users WHERE name = '" + name + "'"); // SQL injection
    }
    public Object load(InputStream in) throws Exception {
        return new ObjectInputStream(in).readObject();                            // unsafe deserialization
    }
    public byte[] digest(String v) throws Exception {
        return MessageDigest.getInstance("MD5").digest(v.getBytes());             // weak hash
    }
    public Process run(String cmd) throws IOException {
        return Runtime.getRuntime().exec("sh -c " + cmd);                         // command injection
    }
}
