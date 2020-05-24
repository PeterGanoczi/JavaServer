package sample;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.Timestamp;
import java.text.SimpleDateFormat;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

@RestController
public class UserController {

    Database db=new Database();



    @RequestMapping("/time")
    public ResponseEntity<String> getTime(@RequestParam(value = "token") String token) {

        if (token == null) {
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\", \"Bad request\"}");
        }
        if (db.checkToken(token)) {
            JSONObject res = new JSONObject();
            DateTimeFormatter format = DateTimeFormatter.ofPattern("HH:mm:ss");
            LocalTime time = LocalTime.now();

            res.put("time", format.format(time));
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
            if (!db.findLogin(obj.getString("login"))) {
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
            //list.add(user);

            //save to mongo
            db.createUser(user);

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

            if (!db.findLogin(obj.getString("login")) && db.checkPassword(obj.getString("login"), obj.getString("password"))) {

                db.loginUser(obj.getString("login"), obj.getString("password"));
                User loggedUser = db.getUser(obj.getString("login"));
                result.put("fname", loggedUser.getFname());
                result.put("lname", loggedUser.getLname());
                result.put("login", loggedUser.getLogin());
                result.put("token", db.getToken(loggedUser.getLogin()));


                //log(loggedUser, "login");
                db.createUserLog(loggedUser.getLogin(), "login");


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
        User user = db.getUser(login);
        if ((user != null) && db.checkToken(token)) {
           // log(user, "logout"); //make log before erase token
            db.createUserLog(user.getLogin(), "logout");

            //user.setToken(null);
            db.logoutUser(obj.getString("login"),token);

            return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body("{\"message\": \"Successfuly logout\"}");
        }
        res.put("error", "Invalid login or token");
        return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(res.toString());
    }



    @RequestMapping("/users")
    public ResponseEntity<String> getUsers(@RequestParam(value = "token") String token) {

        if (token == null) {
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\", \" Token is missing\"}");
        }

        if (db.checkToken(token)) {
            String array;
//

            array=db.getUsers(token);
            return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body(array);
        }

        return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\":\"Invalid token\"}");
    }

    @RequestMapping("/users/{login}")
    public ResponseEntity<String> getOneUser(@RequestParam(value = "token") String token, @PathVariable String login) {

        if (token == null) {
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\": \"Bad request\"}");
        }

        if (db.checkToken(token)) {
            JSONObject obj = new JSONObject();
            User user = db.getUser(login);
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

        if (!db.findLogin(obj.getString("login")) && db.checkPassword(obj.getString("login"), obj.getString("oldpassword"))) {

            User user = db.getUser(obj.getString("login"));
            if (db.checkToken(token) && token.equals(db.getToken(obj.getString("login")))) {

                db.changePassword(user.getPassword(), obj.getString("newpassword"), obj.getString("login"), token);

                return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).
                        body("{\"message\": \"Password for user \"" + obj.getString("login") + "\" is succesfully changed\"}");
            }
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\" error\": \"Invalid token\"}");
        }
        return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\":\"Invalid login or password\"}");
    }

    @RequestMapping(method = RequestMethod.GET, value = "/log?type={logType}")
    public ResponseEntity<String> listOfUserLogs(@RequestBody String data, @RequestHeader(name = "Authorization") String token, @PathVariable String logType) {
        JSONObject obj = new JSONObject(data);
        List<String> userLogs = new ArrayList<>();
        if (!db.checkToken(token)){
            obj.put("error", "invalid token");
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body(data.toString());
        }

        db.listOfUserLogs(obj.getString("login"), token);
//        String login = "";
//        for(User user : list){
//            if( user.getToken()!=null){
//                login = user.getLogin();
//            }
//        }
//
//        org.json.JSONObject logObj = null;
//        for (String log:logs) {
//            logObj = new org.json.JSONObject(log);
//            if (logObj.getString("login").equals(login) && logObj.getString("type").equals(logType)){
//                userLogs.add(log);
//            }
//        }
        return ResponseEntity.status(200).contentType(MediaType.APPLICATION_JSON).body(userLogs.toString());
    }

    @RequestMapping(method = RequestMethod.POST, value = "/message/new")
    public ResponseEntity<String> newMessage(@RequestBody String data, @RequestHeader(name = "Authorization") String token) {
        JSONObject obj = new JSONObject(data);
        User user=db.getUser(obj.getString("from"));

        if (db.getToken(user.getLogin()).equals(token) && !db.findLogin(obj.getString("from")) && !db.findLogin(obj.getString("to"))) {

            JSONObject message = new JSONObject();
            message.put("from", obj.getString("from"));
            message.put("to", obj.getString("to"));
            message.put("message", obj.getString("message"));


            String timeStamp = new SimpleDateFormat("HH:mm:ss dd/MM/yyyy").format(new Date());
            obj.put("time", timeStamp);
            //messages.add(obj.toString());
            db.createMessage(obj.getString("from"),obj.getString("to"),obj.getString("message"));

            return ResponseEntity.status(201).contentType(MediaType.APPLICATION_JSON).body(message.toString());
        } else {
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\":\"Invalid login sender or receiver");
        }
    }

    @RequestMapping(method= RequestMethod.GET, value = "/messages?from={fromLogin}")
    public ResponseEntity<String> getMessages(@RequestBody String data, @RequestHeader(name = "Authorization") String token, @PathVariable String fromLogin) {

        JSONObject obj=new JSONObject(data);
        JSONObject res = new JSONObject();
        JSONArray arr=new JSONArray();

        String login = obj.getString("login");
        if (login == null  || !db.checkToken(token) ) {
            res.put("error", "invalid token or login");
            return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }

        //org.json.JSONObject message;
        JSONObject message;
        if (obj.has("login") && db.checkToken(obj.getString("login"))) {
            res.put("from", obj.getString("login"));
            for(String messages : db.getMessage(login, token)) {

                if (fromLogin==null){
                    JSONObject temp=new JSONObject(messages);
                    arr.put(temp);
                } else if (!db.findLogin(fromLogin)){
                    JSONObject temp=new JSONObject(messages);
                    if(temp.getString("from").equals(fromLogin)){
                        arr.put(temp);
                    }

//                message = new org.json.JSONObject(messages.get(i));
//                if (message.getString("from").equals(fromLogin) && !fromLogin.equals("")){
//                    res.put("message" + i, messages.get(i));
                }
            }
            return ResponseEntity.status(201).contentType(MediaType.APPLICATION_JSON).body(arr.toString());
        } else {
            res.put("error", "missing or wrong login");
            return ResponseEntity.status(401).contentType(MediaType.APPLICATION_JSON).body(res.toString());
        }
    }

    @DeleteMapping(value = "/delete/{login}")
    public ResponseEntity<String> deleteUser(@RequestHeader(value = "token") String token, @PathVariable String login) {
        User user=db.getUser(login);

        if (!db.findLogin(login) && db.getToken(user.getLogin()).equals(token)) {

            db.deleteUser(login, token);
            return ResponseEntity.status(201).contentType(MediaType.APPLICATION_JSON).body("{\"message\": \"User successfully removed\"}");
        } else {
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\": \"Invalid login or token\"}");
        }
    }

    @PatchMapping(value = "update/{login}")
    public ResponseEntity<String> updateLogin(@RequestBody String data, @RequestHeader(value = "token") String token, @PathVariable String login) {
        JSONObject obj = new JSONObject(data);
        User user=db.getUser(login);
        String fname=obj.getString("firstname");
        String lname=obj.getString("lastname");

        if (!db.findLogin(login) && db.getToken(user.getLogin()).equals(token)) {

            db.updateUser(lname, fname, login, token);
            return ResponseEntity.status(201).contentType(MediaType.APPLICATION_JSON).body("Credentials for user "+obj.getString("firstname")+" was successfuly changed");
        } else {
            return ResponseEntity.status(400).contentType(MediaType.APPLICATION_JSON).body("{\"error\": \"Invalid token or login\"}");
        }
    }
}
