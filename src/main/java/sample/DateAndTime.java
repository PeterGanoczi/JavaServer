package sample;

import org.json.JSONObject;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

@RestController
public class DateAndTime {
    List<User> list=new ArrayList<User>();

    public DateAndTime(){
        list.add(new User("Marko", "Kocis", "marko", "heslo123"));
    }

    @RequestMapping(method=RequestMethod.POST, value="/time")
    public ResponseEntity<String> getTime(@RequestBody String data){
        JSONObject obj=new JSONObject(data);
   
        if (!findLogin(data)){
            LocalTime time=LocalTime.now();
            DateTimeFormatter format=DateTimeFormatter.ofPattern("HH:mm:ss");
            obj.put("time", format);
            return ResponseEntity.status(200).body(obj.toString());
        } else {

            obj.put("error", "Invalid token");
            return ResponseEntity.status(400).body(obj.toString());
        }

    }

    @RequestMapping("/time/hour")
    public ResponseEntity<String> getHour(){
        JSONObject obj=new JSONObject();

        LocalTime time=LocalTime.now();
        DateTimeFormatter format=DateTimeFormatter.ofPattern("HH");
        obj.put("hour", format);
        return ResponseEntity.status(200).body(obj.toString());
    }

    @RequestMapping("/primenumber/{number}")
    public ResponseEntity<String> checkPrimeNumber(@PathVariable int number) {

        JSONObject obj = new JSONObject();
        boolean flag = false;
        obj.put("number", number);

        for (int i = 2; i <= number / 2; ++i) {
            if (number % i == 0) {
                flag = true;
                break;
            }
        }
        if (!flag) {
            System.out.println(number + " is a prime number.");
            obj.put("primenumber", true);
            return ResponseEntity.status(200).body(obj.toString());
        } else {
            System.out.println(number + " is not a prime number.");
            obj.put("primenumber", false);
            return ResponseEntity.status(200).body(obj.toString());
        }
    }

    @RequestMapping("/hello")
    public String getHello(){
        return "Hello. How are you? ";
    }

    @RequestMapping("/hello/{name}")
    public String getHelloWithName(@PathVariable String name){
        return "Hello "+name+". How are you? ";
    }

    @RequestMapping("/hi")
    public String getHi(@RequestParam(value="fname") String fname, @RequestParam(value="age") String age){
        return "Hello. How are you? Your name is "+fname+" and you are "+age;
    }

    @RequestMapping(method=RequestMethod.POST, value="/login")
    public String login(@RequestBody String credential){
        System.out.println(credential);
        return "{\"Error\":\"Login already exists\"}";
    }

    @RequestMapping(method = RequestMethod.POST, value = "/logout")
    public ResponseEntity<String> logout(@RequestBody String data) {
        JSONObject obj = new JSONObject(data);
        JSONObject res = new JSONObject();

        System.out.println(obj.getString("login"));
        System.out.println(data);
        res.put("message", "Log out succesful");
        res.put("login", "kral");
        return ResponseEntity.status(200).body(res.toString());
    }

    @RequestMapping(method = RequestMethod.POST, value = "/signup")
    public ResponseEntity<String> signup(@RequestBody String data) {
        System.out.println(data);
        JSONObject obj = new JSONObject(data);
        if (obj.has("fname") && obj.has("lname") && obj.has("login") && obj.has("password")) {
            if (findLogin(obj.getString("login"))) {
                JSONObject res = new JSONObject();
                res.put("error", "user already exists");
                return ResponseEntity.status(400).body(res.toString());
            }

            String password = BCrypt.hashpw(obj.getString("password"), BCrypt.gensalt());
            if (password.isEmpty()) {
                JSONObject res = new JSONObject();
                res.put("error", "password is a mandatory field");
                return ResponseEntity.status(400).body(res.toString());
            }
            User user = new User(obj.getString("fname"), obj.getString("lname"), obj.getString("login"), obj.getString("password"));
            list.add(user);

            JSONObject res = new JSONObject();
            res.put("fname", user.getFname());
            res.put("lname", user.getLname());
            res.put("login", user.getLogin());
            return ResponseEntity.status(201).body(res.toString());
        } else {
            JSONObject res = new JSONObject();
            res.put("error", "invalid input");
            return ResponseEntity.status(400).body(res.toString());
        }
    }

    private boolean findLogin(String login) {
        for (User user : list) {
            if (user.getLogin().equalsIgnoreCase(login))
                return true;
        }
        return false;
    }

}
