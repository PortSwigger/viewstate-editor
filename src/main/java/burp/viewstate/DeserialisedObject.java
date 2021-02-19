package burp.viewstate;

import javax.swing.tree.DefaultMutableTreeNode;
import java.util.ArrayList;
import java.util.List;


public class DeserialisedObject
{
    public enum DeserialisedObjectType
    {
        INT16,
        INT32,
        BYTE,
        CHAR,
        STRING,
        DATETIME,
        DOUBLE,
        FLOAT,
        COLOR,
        ENUM,
        TYPE,
        UNIT,
        SERIALISED_OBJECT,
        NULL,
        BOOLEAN,
        PAIR,
        TRIPLET,
        ARRAY,
        LIST,
        HASHTABLE,
        HASHTABLE_PAIR,
        ERROR
    }

    public final DeserialisedObjectType type;
    public final Object value;
    
    DeserialisedObject(DeserialisedObjectType type, Object value)
    {
        this.type = type;
        this.value = value;
    }

    private void render(TreeRenderer tr, DefaultMutableTreeNode parent)
    {
         DefaultMutableTreeNode node = tr.addNode(parent, this);

        switch (type)
        {
            case PAIR:
            {
                Pair p = (Pair) value;
                p.first.render(tr, node);
                p.second.render(tr, node);
                break;
            }
            case TRIPLET:
            {
                Triplet p = (Triplet) value;
                p.first.render(tr, node);
                p.second.render(tr, node);
                p.third.render(tr, node);
                break;
            }
            case ARRAY:
            {
                DeserialisedArray array = (DeserialisedArray) value;
                DeserialisedObject[] obj = array.values;
                for (DeserialisedObject deserialisedObject : obj)
                {
                    deserialisedObject.render(tr, node);
                }
                break;
            }
            case LIST:
            {
                //noinspection rawtypes
                List a = (ArrayList) value;
                for (Object o : a)
                {
                    ((DeserialisedObject) o).render(tr, node);
                }
                break;
            }
            case HASHTABLE:
            {
                DeserialisedObject[] pairs = (DeserialisedObject[]) value;
                for (DeserialisedObject pair : pairs)
                {
                    pair.render(tr, node);
                }
            }
        }
    }
    
    public void render(TreeRenderer tr)
    {
        render(tr, tr.getRoot());
        tr.expandAll();
    }
    
    
    @Override
    public String toString()
    {
        switch (type)
        {
            case PAIR:
            case TRIPLET:
                return value.toString();
            case ARRAY:                
            {
                DeserialisedArray array = (DeserialisedArray) value;
                if (array.type instanceof Class)
                {
                    return "array of " + ((Class<?>) array.type).getSimpleName();
                }
                else
                {
                    return "array of " + array.type;
                }
            }
            case LIST:
                return value.toString();
            case HASHTABLE:
                return "hashtable";
            case HASHTABLE_PAIR:
            {
                DeserialisedObject[] pair = (DeserialisedObject[]) value;
                return pair[0].value + " = " + pair[1].value;
            }
            
            case ERROR:
                return "*** ERROR ***";
            
            case TYPE:
            {
                if (value instanceof Class)
                {
                    return ((Class<?>) value).getSimpleName();
                }
                else
                {
                    return value.toString();
                }
            }
                
            default:
                if (value != null)
                {
                    return value.toString();
                }
        }
        return null;
    }
}