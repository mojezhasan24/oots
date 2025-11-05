import java.util.*;
import java.io.*;

public class ListRealStudents {
    public static void main(String[] args) {
        try {
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data/students.ser"));
            java.util.List list = (java.util.List) ois.readObject();
            ois.close();

            for (Object o : list) {
                java.lang.reflect.Method getId = o.getClass().getMethod("getStudentId");
                java.lang.reflect.Method getRoll = o.getClass().getMethod("getRollNumber");
                java.lang.reflect.Method getName = o.getClass().getMethod("getName");
                System.out.println(
                    "studentId=" + getId.invoke(o)
                    + ", roll=" + getRoll.invoke(o)
                    + ", name=" + getName.invoke(o)
                );
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
