package sample;

import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;


@RestController
public class TimeController {


    @RequestMapping("/time/hour")
    public ResponseEntity<String> getHour(){
        JSONObject obj=new JSONObject();

        LocalTime time=LocalTime.now();
        DateTimeFormatter format=DateTimeFormatter.ofPattern("HH");
        obj.put("hour", format);
        return ResponseEntity.status(200).body(obj.toString());
    }


}
