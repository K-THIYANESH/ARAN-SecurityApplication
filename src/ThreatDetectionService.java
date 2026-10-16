public class ThreatDetectionService {

    public void analyze()
    {

        System.out.println("\nThreat Analysis");

        for(SecurityEvent e : DataStore.events)
        {

            String threat="LOW";

            if(e.getEventType().equals("Malware"))
                threat="CRITICAL";

            else if(e.getEventType().equals("Login Failure"))
                threat="HIGH";

            else if(e.getEventType().equals("USB Inserted"))
                threat="MEDIUM";

            System.out.println(e.getUsername()+" -> "+threat);

        }

        LoggerService.log("Threat Analysis Completed");

    }

}