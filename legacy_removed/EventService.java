import java.util.Scanner;

public class EventService {

    public void addEvent(Scanner sc)
    {

        System.out.print("Username : ");
        String user = sc.nextLine();

        System.out.println("Event Type");
        System.out.println("1.Login Success");
        System.out.println("2.Login Failure");
        System.out.println("3.File Access");
        System.out.println("4.USB Inserted");
        System.out.println("5.Malware");

        System.out.print("Choice : ");
        int ch = sc.nextInt();
        sc.nextLine();

        String event = "";

        switch(ch)
        {
            case 1:event="Login Success";break;
            case 2:event="Login Failure";break;
            case 3:event="File Access";break;
            case 4:event="USB Inserted";break;
            case 5:event="Malware";break;
        }

        System.out.print("IP Address : ");
        String ip = sc.nextLine();

        SecurityEvent e = new SecurityEvent(user,event,ip);

        DataStore.events.add(e);

        LoggerService.log("New Event Added");

        System.out.println("Event Added Successfully");

    }

    public void viewEvents()
    {

        System.out.println("\n------ EVENTS ------");

        for(SecurityEvent e : DataStore.events)
        {
            System.out.println("------------------------");
            System.out.println("User : "+e.getUsername());
            System.out.println("Event : "+e.getEventType());
            System.out.println("IP : "+e.getIpAddress());
        }

    }

}