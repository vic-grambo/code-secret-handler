// Sample Java file with hardcoded secrets
public class Database {
    private static final String DB_PASSWORD = "javaDbPass!2024";
    private static final String DB_HOST = "prod-db.internal.example.com";
    private static final String DB_USERNAME = "db_admin_user";

    public static String getConnectionString() {
        return "jdbc:postgresql://" + DB_HOST + ":5432/app?user=" + DB_USERNAME + "&password=" + DB_PASSWORD;
    }
}
