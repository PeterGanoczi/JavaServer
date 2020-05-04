package sample;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@RestController
public class UserController {
    List<User> list = new ArrayList<User>();
    List<String> logs = new ArrayList<String>();

    public UserController() {
        list.add(new User("Peter", "Ganoczi", "peto", "heslo"));
    }


    @RequestMapping("/time")
    public ResponseEntity<String> getTime(@RequestParam(value = "token") String token) {

        if (token == null) {
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\", \"Bad request\"}");
        }
        if (isTokenValid(token)) {
            JSONObject res = new JSONObject();
            LocalTime time = LocalTime.now();
            DateTimeFormatter format = DateTimeFormatter.ofPattern("HH:mm:ss");

            res.put("time", format);
            return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        } else {

            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\", \"Invalid token\"}");
        }

    }

    @RequestMapping(method = RequestMethod.POST, value = "/signup")
    public ResponseEntity<String> signup(@RequestBody String data) {
        System.out.println(data);
        JSONObject obj = new JSONObject(data);

        if (obj.has("fname") && obj.has("lname") && obj.has("login") && obj.has("password")) {
            if (existLogin(obj.getString("login"))) {
                JSONObject res = new JSONObject();
                res.put("error", "user already exists");
                return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            }

            String password = obj.getString("password");
            if (password.isEmpty()) {
                JSONObject res = new JSONObject();
                res.put("error", "password is a mandatory field");
                return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
            }
            String hashPass = BCrypt.hashpw(obj.getString("password"), BCrypt.gensalt(12));

            User user = new User(obj.getString("fname"), obj.getString("lname"), obj.getString("login"), hashPass);
            list.add(user);

            JSONObject res = new JSONObject();
            res.put("fname", user.getFname());
            res.put("lname", user.getLname());
            res.put("login", user.getLogin());
            return ResponseEntity.status(201).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        } else {
            JSONObject res = new JSONObject();
            res.put("error", "invalid input");
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }
    }

    @RequestMapping(method = RequestMethod.POST, value = "/login")
    public ResponseEntity<String> login(@RequestBody String credential) {
        JSONObject obj = new JSONObject(credential);

        if (obj.has("login") && obj.has("password")) {
            JSONObject result = new JSONObject();

            if (obj.getString("login").isEmpty() || obj.getString("password").isEmpty()) {
                result.put("error", "Login and password are required");
                return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(result.toString());
            }

            if (existLogin(obj.getString("login")) && checkPassword(obj.getString("login"), obj.getString("password"))) {

                User loggedUser = getUser(obj.getString("login"));
                result.put("fname", loggedUser.getFname());
                result.put("lname", loggedUser.getLname());
                result.put("login", loggedUser.getLogin());
                String token = generateToken();
                result.put("token", token);
                loggedUser.setToken(token);

                log(loggedUser, "login");
                return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body(result.toString());
            } else {
                result.put("error", "Invalid login or password");
                return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(result.toString());
            }
        } else {
            JSONObject result = new JSONObject();
            result.put("error", "Missing login or password");
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(result.toString());
        }
    }

    @RequestMapping(method = RequestMethod.POST, value = "/logout")
    public ResponseEntity<String> logout(@RequestBody String data, @RequestHeader(name = "Authorization") String token) {
        JSONObject obj = new JSONObject(data);
        JSONObject res = new JSONObject();

        String login = obj.getString("login");
        User user = getUser(login);
        if ((user != null) && isTokenValid(token)) {
            log(user, "logout"); //make log before erase token

            user.setToken(null);

            return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body("{\"message\": \"Successfuly logout\"}");
        }
        res.put("error", "Invalid login or token");
        return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
    }

    private String generateToken() {
        int size = 25;
        Random rnd = new Random();
        String generatedString = "";
        for (int i = 0; i < size; i++) {
            int type = rnd.nextInt(4);

            switch (type) {
                case 0:
                    generatedString += (char) ((rnd.nextInt(26)) + 65);
                    break;
                case 1:
                    generatedString += (char) ((rnd.nextInt(10)) + 48);
                    break;
                default:
                    generatedString += (char) ((rnd.nextInt(26)) + 97);
            }
        }
        return generatedString;
    }

    public boolean isTokenValid(String token) {
        for (User users : list)
            if (users.getToken() != null && users.getToken().equals(token))
                return true;

        return false;
    }

    private boolean existLogin(String login) {
        for (User user : list) {
            if (user.getLogin().equalsIgnoreCase(login))
                return true;
        }
        return false;
    }

    private boolean checkPassword(String login, String password) {
        String pass;
        User user = getUser(login);
        if (user != null) {
            if (BCrypt.checkpw(password, user.getPassword()))
                return true;
        }
        return false;
    }

    private User getUser(String login) {
        for (User user : list) {
            if (user.getLogin().equals(login))
                return user;
        }
        return null;
    }

    @RequestMapping("/users")
    public ResponseEntity<String> getUsers(@RequestParam(value = "token") String token) {

        if (token == null) {
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\", \" Token is missing\"}");
        }

        if (isTokenValid(token)) {
            JSONArray array = new JSONArray();
            for (User user : list) {
                JSONObject obj = new JSONObject();
                obj.put("fname", user.getFname());
                obj.put("lname", user.getLname());
                obj.put("login", user.getLogin());
                array.put(obj);
            }
            return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body(array.toString());
        }

        return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\":\"Invalid token\"}");
    }

    @RequestMapping("/users/{login}")
    public ResponseEntity<String> getOneUser(@RequestParam(value = "token") String token, @PathVariable String login) {

        if (token == null) {
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\": \"Bad request\"}");
        }

        if (isTokenValid(token)) {
            JSONObject obj = new JSONObject();
            User user = getUser(login);
            if (user == null) {
                return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\": \"User does not exists}");
            }
            obj.put("fname", user.getFname());
            obj.put("lname", user.getLname());
            obj.put("login", user.getLogin());

            return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body(obj.toString());
        }
        return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\":\"Invalid token\"}");
    }

    @RequestMapping(method = RequestMethod.POST, value = "/changepassword")
    public ResponseEntity<String> changePassword(@RequestBody String credentials, @RequestHeader(name = "Authorization") String token) {
        JSONObject obj = new JSONObject(credentials);

        if (token == null) {
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\":\"Token is missing\"}");
        }

        if (existLogin(obj.getString("login")) && checkPassword(obj.getString("login"), obj.getString("oldpassword"))) {

            User user = getUser(obj.getString("login"));
            if (isTokenValid(token) && token.equals(user.getToken())) {

                String hashPass = BCrypt.hashpw(obj.getString("newpassword"), BCrypt.gensalt(12));
                user.setPassword(hashPass);

                return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).
                        body("{\"message\": \"Password for user \"" + user.getLogin() + "\" is succesfully changed\"}");
            }
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\" error\": \"Invalid token\"}");
        }
        return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\":\"Invalid login or password\"}");
    }

    private void log(User user, String type) {
        JSONObject log = new JSONObject();
        log.put("type", type);
        log.put("login", user.getLogin());
        log.put("datetime", getTime(user.getToken()));
        logs.add(log.toString());
    }

    @RequestMapping(method = RequestMethod.GET, value = "/log")
    public ResponseEntity<String> listOfUserLogs(@RequestBody String login, @RequestHeader(name = "Authorization") String token) {
        JSONObject data=new JSONObject(login);

        if (existLogin(data.getString("login"))) {
            User user = getUser(login);


            if (user.getToken().equals(token) && user.getToken()!=null) {
                List<String> userLogs = new ArrayList<>();

                for (String log : logs) {
                    JSONObject obj = new JSONObject(logs);
                    if (obj.getString("login").equals(login)) {
                        userLogs.add(log);
                    }
                }
                return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body(userLogs.toString());
            }
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\": \" Invalid token\"}");
        }
        return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\": \"No such login\"}");

    }
}
