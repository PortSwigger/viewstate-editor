package burp.viewstate;

public class SerialisedObject
{
    public String data;
    
    SerialisedObject(String data)
    {
        this.data = data;
    }
    
    @Override
    public String toString()
    {
        return data;
    }
}
