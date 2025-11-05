import java.util.*;
import java.io.*;

public class UpdateSimHash {
    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java UpdateSimHash <rollNumber> <simHash>");
            return;
        }

        String rollToFind = args[0];
        String newHash = args[1];

        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data/students.ser"))) {
            List<?> list = (List<?>) ois.readObject();
            boolean updated = false;

            for (Object o : list) {
                String roll = (String) o.getClass().getMethod("getRollNumber").invoke(o);
                if (roll.equals(rollToFind)) {
                    o.getClass().getMethod("setSimHash", String.class).invoke(o, newHash);
                    updated = true;
                    break;
                }
            }

            if (updated) {
                try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("data/students.ser"))) {
                    oos.writeObject(list);
                }
                System.out.println("✅ Updated simHash for student " + rollToFind);
            } else {
                System.out.println("Student " + rollToFind + " not found.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
