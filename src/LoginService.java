import java.util.Scanner;

public class LoginService {

    public boolean login(Scanner sc)
    {

        System.out.println("===== LOGIN =====");

        System.out.print("Username : ");
        String user = sc.nextLine();

        System.out.print("Password : ");
        String pass = sc.nextLine();

        if(user.equals("admin") && pass.equals("admin123"))
        {
            System.out.println("Login Successful");
            return true;
        }

        System.out.println("Invalid Login");

        return false;

    }

}