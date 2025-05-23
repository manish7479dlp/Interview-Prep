//static data

import java.sql.*;

public class JdbcExample {
    public static void main(String[] args) throws Exception {
        // 1. Load Driver
        Class.forName("com.mysql.cj.jdbc.Driver");

        // 2. Connect to DB
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/mydatabase", "root", "password");

        // 3. Create Statement
        Statement stmt = conn.createStatement();

        // 4. Execute Query
        ResultSet rs = stmt.executeQuery("SELECT * FROM users");

        // 5. Process Result
        while (rs.next()) {
            System.out.println(rs.getString("username"));
        }

        // 6. Close resources
        rs.close();
        stmt.close();
        conn.close();
    }
}


//dynamic data
import java.sql.*;

public class InsertDynamicData {
    public static void main(String[] args) {
        String jdbcUrl = "jdbc:mysql://localhost:3306/mydatabase";
        String username = "root";
        String password = "password";

        // Dynamic data (e.g., from user input)
        int userId = 101;
        String userName = "John Doe";
        String userEmail = "john@example.com";

        try {
            // 1. Load the JDBC Driver (optional for JDBC 4+)
            Class.forName("com.mysql.cj.jdbc.Driver");

            // 2. Establish Connection
            Connection conn = DriverManager.getConnection(jdbcUrl, username, password);

            // 3. Prepare SQL with placeholders (?)
            String sql = "INSERT INTO users (id, name, email) VALUES (?, ?, ?)";

            // 4. Create PreparedStatement
            PreparedStatement pstmt = conn.prepareStatement(sql);

            // 5. Set dynamic data
            pstmt.setInt(1, userId);
            pstmt.setString(2, userName);
            pstmt.setString(3, userEmail);

            // 6. Execute Update
            int rowsInserted = pstmt.executeUpdate();
            if (rowsInserted > 0) {
                System.out.println("A new user was inserted successfully!");
            }

            // 7. Close connection
            pstmt.close();
            conn.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}




// 📌 PreparedStatement Methods for Setting Dynamic Values:

// | Method                   | Use for                    |
// | ------------------------ | -------------------------- |
// | `setInt(index, val)`     | Integer values             |
// | `setString(index, val)`  | String/text                |
// | `setDouble(index, val)`  | Decimal values             |
// | `setBoolean(index, val)` | Boolean (true/false)       |
// | `setDate(index, val)`    | SQL Date (`java.sql.Date`) |


