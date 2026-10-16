import java.util.Scanner;

public class Menu {

    EventService eventService = new EventService();
    ThreatDetectionService threatService = new ThreatDetectionService();
    ReportService reportService = new ReportService();

    public void start(Scanner sc)
    {

        int choice;

        do
        {
            System.out.println("\n====== ARAN CLI ======");
            System.out.println("1. Add Event");
            System.out.println("2. View Events");
            System.out.println("3. Analyze Threat");
            System.out.println("4. Generate Report");
            System.out.println("5. Exit");

            System.out.print("Enter Choice : ");
            choice = sc.nextInt();
            sc.nextLine();

            switch(choice)
            {
                case 1:
                    eventService.addEvent(sc);
                    break;

                case 2:
                    eventService.viewEvents();
                    break;

                case 3:
                    threatService.analyze();
                    break;

                case 4:
                    reportService.generate();
                    break;

                case 5:
                    System.out.println("Thank You");
                    break;

                default:
                    System.out.println("Invalid Choice");
            }

        }while(choice!=5);

    }
}