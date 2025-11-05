import java.util.*;
import java.io.*;

public class UpdateSimHash {
    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java UpdateSimHash <studentId> <simHash>");
            return;
        }

        String idToFind = args[0];
        String newHash = args[1];

        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data/students.ser"))) {
            List<?> list = (List<?>) ois.readObject();
            boolean updated = false;

            for (Object o : list) {
                String id = (String) o.getClass().getMethod("getStudentId").invoke(o);
                if (id.equals(idToFind)) {
                    o.getClass().getMethod("setSimHash", String.class).invoke(o, newHash);
                    updated = true;
                    break;
                }
            }

            if (updated) {
                try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("data/students.ser"))) {
                    oos.writeObject(list);
                }
                System.out.println("✅ Updated simHash for student " + idToFind);
            } else {
                System.out.println("Student " + idToFind + " not found.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

