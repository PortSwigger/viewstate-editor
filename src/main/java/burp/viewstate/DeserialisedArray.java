package burp.viewstate;

public class DeserialisedArray
{
    public Object type;
    public DeserialisedObject[] values;
    
    DeserialisedArray(Object type, DeserialisedObject[] values)
    {
        this.type = type;
        this.values = values;
    }
    
    @Override
    public String toString()
    {
        return "array of " + type.toString();
    }
}
