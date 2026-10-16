package aran.storage;

import aran.util.AppConfig;
import java.sql.*;

public class MySqlDatabase implements AutoCloseable {
    private Connection connection;
    public void connect() throws SQLException {
        String url=AppConfig.get("db.url","jdbc:mysql://localhost:3306/aran");
        String user=AppConfig.get("db.user","root"); String pass=AppConfig.get("db.password","");
        connection=DriverManager.getConnection(url,user,pass);
    }
    public boolean isConnected(){return connection!=null;}
    public Connection connection(){return connection;}
    public void saveEvent(String id,String timestamp,String username,String type,String ip,String source,String details) throws SQLException {
        String sql="INSERT INTO security_events(event_id,event_time,username,event_type,source_ip,source,details) VALUES(?,?,?,?,?,?,?)";
        try(PreparedStatement ps=connection.prepareStatement(sql)){ps.setString(1,id);ps.setString(2,timestamp);ps.setString(3,username);ps.setString(4,type);ps.setString(5,ip);ps.setString(6,source);ps.setString(7,details);ps.executeUpdate();}
    }
    public void close(){try{if(connection!=null)connection.close();}catch(SQLException ignored){}}
}
