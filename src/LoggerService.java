import java.io.FileWriter;
import java.io.IOException;

public class LoggerService {

    public static void log(String message)
    {

        try
        {

            FileWriter fw = new FileWriter("logs/security.log",true);

            fw.write(message+"\n");

            fw.close();

        }

        catch(IOException e)
        {

        }

    }

}