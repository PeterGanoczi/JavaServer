package sample;

public class User {
    private String fname;
    private String lname;
    private String login;
    private String password;
    private String token;

    public User(String fname, String lname, String login, String password) {
        this.fname = fname;
        this.lname = lname;
        this.login = login;
        this.password = password;
        token = null;
    }

    public String getFname() {
        return fname;
    }

    public String getLname() {
        return lname;
    }

    public String getLogin() {
        return login;
    }

    public String getPassword() {
        return password;
    }

    public String getToken() {
        return token;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public void setFname(String fname) {
        this.fname = fname;
    }

    public void setLname(String lname) {
        this.lname = lname;
    }
}
