package sample;

//import com.mongodb.MongoClient;

import com.mongodb.*;
import com.mongodb.client.*;
import com.mongodb.client.MongoClient;
import com.mongodb.client.model.Filters;
import org.bson.BsonArray;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.json.JSONObject;
import org.mindrot.jbcrypt.BCrypt;

import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

public class Database {

    public final String uri = "mongodb://localhost:27017";
    public final String dbName = "chatApp";
    public final String usersCollection = "users";
    public final String logsCollection = "usersLogs";
    public final String messageCollection = "messages";
    public static MongoDatabase database;


    public void connection() {
        try (MongoClient mongoClient = MongoClients.create(uri)) {
            database = mongoClient.getDatabase(dbName);

            //control print of connection
            System.out.println("Connection successful");
            for (String name : database.listCollectionNames()) {
                System.out.println(name);
            }
        }
    }

    public void createUser(User user) {

        try (MongoClient mongoClient = MongoClients.create(uri)) {
            database = mongoClient.getDatabase(dbName);

            MongoCollection<Document> collection = database.getCollection(usersCollection);

            Document doc = new Document("fname", user.getFname())
                    .append("lname", user.getLname())
                    .append("login", user.getLogin())
                    .append("password", user.getPassword())
                    .append("token", user.getToken());

            System.out.println("vytvoril som noveho user v mongoDB");

            collection.insertOne(doc);
        }
    }

    public boolean loginUser(String login, String password) {
        try (MongoClient mongoClient = MongoClients.create(uri)) {
            database = mongoClient.getDatabase(dbName);

            MongoCollection<Document> collection = database.getCollection(usersCollection);

            BasicDBObject loginQuery = new BasicDBObject();
            loginQuery.put("login", login);

            Bson filter = Filters.eq("login", login);
            Document myDoc = collection.find(filter).first();

            assert myDoc != null;
            String hashed = myDoc.getString("password");
            User temp = getUser(login);

            if (!findLogin(login) && BCrypt.checkpw(password, hashed) && temp.getLogin().equals(login)) {
                BasicDBObject token = new BasicDBObject().append("token", generateToken());
                temp.setToken(token.getString("token"));
                collection.updateOne(loginQuery, new BasicDBObject("$set", token));
                mongoClient.close();
                return true;
            }
            mongoClient.close();
            return false;


        }
    }

    public boolean logoutUser(String login, String token) {
        try (MongoClient mongoClient = MongoClients.create(uri)) {
            database = mongoClient.getDatabase(dbName);

            MongoCollection<Document> collection = database.getCollection(usersCollection);

            BasicDBObject loginQuery = new BasicDBObject();
            loginQuery.put("login", login);
            loginQuery.put("token", token);

            User tempUser = getUser(login);
            if (!findLogin(login) && checkToken(token) && tempUser.getLogin().equals(login)) {
                collection.updateOne(loginQuery, new BasicDBObject("$unset", new BasicDBObject("token", token)));
                mongoClient.close();
                return true;
            }
            mongoClient.close();
            return false;
        }
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


    public boolean findLogin(String login) {
        try (MongoClient mongoClient = MongoClients.create(uri)) {
            database = mongoClient.getDatabase(dbName);
            MongoCollection<Document> collection = database.getCollection(usersCollection);

            BasicDBObject loginQuery = new BasicDBObject();
            loginQuery.put("login", login);
            long count = collection.countDocuments(loginQuery);

            if (count == 0) {
                mongoClient.close();
                return true;
            }
            mongoClient.close();
            return false;
        }
    }

    public User getUser(String login) {
        try (MongoClient mongoClient = MongoClients.create(uri)) {
            database = mongoClient.getDatabase(dbName);
            MongoCollection<Document> collection = database.getCollection(usersCollection);

            Bson bsonFilter = Filters.eq("login", login);
            Document myDoc = collection.find(bsonFilter).first();


            if (!findLogin(login)) {
                assert myDoc != null;

                return new User(myDoc.getString("fname"), myDoc.getString("lname"),
                        myDoc.getString("login"), myDoc.getString("password"));

            }
            mongoClient.close();
            return null;
        }
    }

    public String getUsers(String token) {
        try (MongoClient mongoClient = MongoClients.create(uri)) {
            database = mongoClient.getDatabase(dbName);
            MongoCollection<Document> collection = database.getCollection(usersCollection);
            Document document = null;
            MongoCursor<Document> cursor = collection.find().iterator();


            while (cursor.hasNext()) {
                document= cursor.next();

            }
            return document.toJson();
        }

    }

    public String getToken(String login) {
        try (MongoClient mongoClient = MongoClients.create(uri)) {
            database = mongoClient.getDatabase(dbName);
            MongoCollection<Document> collection = database.getCollection(usersCollection);

            Bson bsonFilter = Filters.eq("login", login);
            Document myDoc = collection.find(bsonFilter).first();

            if (!findLogin(login)) {
                assert myDoc != null;
                return myDoc.getString("token");
            }

        }
        return null;
    }

    public boolean checkToken(String token) {
        try (MongoClient mongoClient = MongoClients.create(uri)) {
            database = mongoClient.getDatabase(dbName);
            MongoCollection<Document> collection = database.getCollection(usersCollection);

            BasicDBObject loginQuery = new BasicDBObject();
            loginQuery.append("token", token);

            long count = collection.countDocuments(loginQuery);
            if (count > 0) {
                mongoClient.close();
                return true;
            }
            mongoClient.close();
            return false;
        }
    }

    public boolean changePassword(String oldPassword, String newPassword, String login, String token){
        try (MongoClient mongoClient = MongoClients.create(uri)) {
            database = mongoClient.getDatabase(dbName);
            MongoCollection<Document> collection = database.getCollection(usersCollection);

            BasicDBObject loginQuery=new BasicDBObject();
            loginQuery.append("login", login);
            loginQuery.append("password",oldPassword);
            loginQuery.append("token",token);

            User tempUser=getUser(login);

            if (checkToken(token) && !findLogin(login) && tempUser.getLogin().equals(login)){
                collection.updateOne(loginQuery, new BasicDBObject("$set", new BasicDBObject("password", hashPass(newPassword))));
                mongoClient.close();
                return true;
            }
            mongoClient.close();
            return false;
        }

    }

    public boolean checkPassword(String login, String password) {
        try (MongoClient mongoClient = MongoClients.create(uri)) {
            database = mongoClient.getDatabase(dbName);
            MongoCollection<Document> collection = database.getCollection(usersCollection);

            BasicDBObject loginQuery = new BasicDBObject();
            loginQuery.put("login", login);
            loginQuery.put("password", password);
            User temp = getUser(login);


            if (!findLogin(login)) {
                mongoClient.close();
                return BCrypt.checkpw(password, temp.getPassword());
            }
            mongoClient.close();
            return false;
        }
    }

    public String hashPass(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(12));

    }

    public void createUserLog(String login, String type) {
        try (MongoClient mongoClient = MongoClients.create(uri)) {
            database = mongoClient.getDatabase(dbName);
            MongoCollection<Document> collection = database.getCollection(logsCollection);

            String timeStamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());

            Document doc = new Document("type", type)
                    .append("login", login)
                    .append("datetime", timeStamp);

            System.out.println("vytvoril som novy log");
            collection.insertOne(doc);
        }
    }

    public List<String> listOfUserLogs(String login, String token) {
        try (MongoClient mongoClient = MongoClients.create(uri)) {
            database = mongoClient.getDatabase(dbName);
            MongoCollection<Document> logCol = database.getCollection(logsCollection);
            MongoCollection<Document> userCol = database.getCollection(usersCollection);

            BasicDBObject loginQuery = new BasicDBObject();
            loginQuery.append("type", login);

            Bson bsonFilter = Filters.eq("login", login);
            Document myDoc = logCol.find(bsonFilter).first();
            FindIterable<Document> ss = logCol.find(bsonFilter);

            BasicDBObject checkQuery = new BasicDBObject();
            checkQuery.append("login", login);
            checkQuery.append("token", token);

            FindIterable<Document> doc = userCol.find(checkQuery);

            User temp = getUser(login);

            List<String> tem = new ArrayList<>();
            JSONObject obj = new JSONObject();

            if (!findLogin(login) && checkToken(token) && temp.getLogin().equals(login) && myDoc != null) {
                if (doc.iterator().hasNext()) {

                    for (Document p : ss) {
                        obj.put("type", p.getString("type"));
                        obj.put("login", p.getString("login"));
                        obj.put("datetime", p.getString("datetime"));
                        tem.add(obj.toString());
                    }
                } else {
                    return null;
                }
                return tem;
            }

            return null;
        }
    }

    // connection
    // pridavanie usera

    //robot 3T gui pre mongo
}
