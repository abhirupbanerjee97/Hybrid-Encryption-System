/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityofebasedsystemproject;
import java.sql.*;
import javax.swing.*;

/**
 *
 * @author ABHIRUP
 */
public class MySQLConnect {
    Connection conn=null;
    public static Connection ConnectDB(){
        try{
            Class.forName("com.mysql.jdbc.Driver");
            Connection conn=DriverManager.getConnection("jdbc:mysql://Localhost/testdb","root","password");
            //JOptionPane.showMessageDialog(null,"Connected to database");
            return conn;
            
        }
    catch(Exception e){
        JOptionPane.showMessageDialog(null,e);
        return null;
    }
    }
    
}
