package burp.viewstate;

class Colour
{
    private final String name;
    
    Colour(int identifier, boolean known)
    {
        if (known)
        {
            name = "KnownColor[" + identifier + "]";
        }
        else
        {
            name = String.format("RGB [%06x]", identifier & 0xffffff);
        }
    }
    
    Colour()
    {
        name = "[empty]";
    }
    
    @Override
    public String toString()
    {
        return name;
    }
}
