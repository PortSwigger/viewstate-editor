package burp.viewstate;

class Enum
{
    Object type;
    int index;
    
    Enum(Object type, int index)
    {
        this.type = type;
        this.index = index;
    }
    
    @Override
    public String toString()
    {
        return "index: " + index + ", type: " + type;
    }
}
