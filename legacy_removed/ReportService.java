import java.io.FileWriter;
import java.io.IOException;

public class ReportService {

    public void generate()
    {

        try
        {

            FileWriter fw = new FileWriter("reports/report.txt");

            fw.write("ARAN CLI REPORT\n\n");

            for(SecurityEvent e : DataStore.events)
            {
                fw.write("User : "+e.getUsername()+"\n");
                fw.write("Event : "+e.getEventType()+"\n");
                fw.write("IP : "+e.getIpAddress()+"\n");
                fw.write("----------------------\n");
            }

            fw.close();

            LoggerService.log("Report Generated");

            System.out.println("Report Saved");

        }

        catch(IOException e)
        {
            System.out.println("Error");
        }

    }

}