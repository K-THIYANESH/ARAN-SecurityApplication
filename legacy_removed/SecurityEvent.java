public class SecurityEvent {

    private String username;
    private String eventType;
    private String ipAddress;

    public SecurityEvent(String username,String eventType,String ipAddress)
    {
        this.username=username;
        this.eventType=eventType;
        this.ipAddress=ipAddress;
    }

    public String getUsername()
    {
        return username;
    }

    public String getEventType()
    {
        return eventType;
    }

    public String getIpAddress()
    {
        return ipAddress;
    }

}