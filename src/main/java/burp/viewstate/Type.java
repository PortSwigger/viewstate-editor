package burp.viewstate;

public class Type
{
    private final String name;
    
    Type(String name)
    {
        int trunc = name.indexOf(",");

        if (trunc != -1)
        {
            name = name.substring(0, trunc);
        }
        
        this.name = name;
    }
    
    @Override
    public String toString()
    {
        return name;
    }
}
