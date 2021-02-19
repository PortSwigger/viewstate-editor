package burp.viewstate;

import burp.IExtensionHelpers;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static burp.viewstate.DeserialisedObject.DeserialisedObjectType.*;
import static burp.viewstate.ViewState.Version.V20;

public class V20Deserialiser
{
    private final static Class<?>[] KNOWN_TYPES = new Class[]{Object.class, Integer.class, String.class, Boolean.class};

    private final byte[] raw;
    private final InputStream is;
    private final IExtensionHelpers helpers;

    private boolean errorOccurred;

    private List<Object> typeList;
    private String[] stringList;
    private int stringTableCount;
    private int[] buffer;

    public V20Deserialiser(byte[] base64, IExtensionHelpers helpers)
    {
        this.raw = base64;
        this.is = new ByteArrayInputStream(raw);
        this.helpers = helpers;
    }

    private void initializeDeserializer()
    {
        typeList = new ArrayList<>();
        for (Class<?> knownType : KNOWN_TYPES)
        {
            addDeserialisationTypeReference(knownType);
        }
        stringList = new String[0xff];
        stringTableCount = 0;
        buffer = new int[0x10];
    }


    public static boolean canDeserialise(byte[] b)
    {
        return b.length > 1 && b[0] == -1 && b[1] == 1;
    }

    public ViewState deserialise() throws Exception
    {
        if (readByte() == 0xff && readByte() == 0x01)
        {
            ViewState vs = new ViewState(V20);

            initializeDeserializer();
            vs.value = deserialiseValue();

            if (!errorOccurred)
            {
                switch (is.available())
                {
                    case 0:
                        vs.macEnabled = false;
                        break;
                    case 20:
                    case 32:
                        vs.macEnabled = true;
                        break;
                    default:
                        errorOccurred = true;
                        break;
                }
            }

            vs.errorOccurred = errorOccurred;
            vs.raw = raw;

            return vs;
        }

        throw new Exception("Not a valid ASP.NET 2.0 LOS stream");
    }

    private DeserialisedObject deserialiseValue()
    {
        if (errorOccurred)
        {
            return new DeserialisedObject(ERROR, null);
        }

        try
        {

            int token = is.read();

            switch (token)
            {
                case 1:     // int16
                    return new DeserialisedObject(INT16, readInt16());

                case 2:     // int32
                    return new DeserialisedObject(INT32, readEncodedInt32());

                case 3:     // byte
                    return new DeserialisedObject(BYTE, readByte());

                case 4:     // char
                    return new DeserialisedObject(CHAR, (char) readByte());

                case 5:     // string
                    return new DeserialisedObject(STRING, readString());

                case 6:     // date/time
                    return new DeserialisedObject(DATETIME, readInt64());

                case 7:     // double
                    return new DeserialisedObject(DOUBLE, readDouble());

                case 8:     // float
                    return new DeserialisedObject(FLOAT, readFloat());

                case 9:     // color from rgb
                    return new DeserialisedObject(COLOR, new Colour(readInt32(), false));

                case 0xa:   // known color
                    return new DeserialisedObject(COLOR, new Colour(readEncodedInt32(), true));

                case 0xb:  // enum
                {
                    Object type = readType();
                    int index = readEncodedInt32();
                    return new DeserialisedObject(ENUM, new Enum(type, index));
                }

                case 0xc:   // Color.Empty
                    return new DeserialisedObject(COLOR, new Colour());

                case 0xf:   // pair
                    return new DeserialisedObject(PAIR, new Pair(deserialiseValue(), deserialiseValue()));

                case 0x10:  // triplet
                    return new DeserialisedObject(TRIPLET, new Triplet(deserialiseValue(), deserialiseValue(), deserialiseValue()));

                case 0x14:  // array of objects
                {
                    Object type = readType();
                    int length = readEncodedInt32();
                    DeserialisedObject[] array = new DeserialisedObject[length];

                    for (int i = 0; i < length; i++)
                    {
                        array[i] = deserialiseValue();
                    }

                    return new DeserialisedObject(ARRAY, new DeserialisedArray(type, array));
                }

                case 0x15:  // array of strings
                {
                    int capacity = readEncodedInt32();
                    DeserialisedObject[] array = new DeserialisedObject[capacity];

                    for (int i = 0; i < capacity; i++)
                    {
                        array[i] = new DeserialisedObject(STRING, readString());
                    }

                    return new DeserialisedObject(ARRAY, new DeserialisedArray(String.class, array));
                }

                case 0x16:  // list
                {
                    int capacity = readEncodedInt32();
                    List<DeserialisedObject> list = new ArrayList<>(capacity);

                    for (int i = 0; i < capacity && !errorOccurred; i++)
                    {
                        list.add(deserialiseValue());
                    }

                    return new DeserialisedObject(LIST, list);
                }

                case 0x17:  // HybridDictionary
                case 0x18:  // Hashtable
                {
                    int capacity = readEncodedInt32();
                    List<DeserialisedObject> list = new ArrayList<>(capacity);
                    for (int i = 0; i < capacity; i++)
                    {
                        list.add(new DeserialisedObject(HASHTABLE_PAIR, new DeserialisedObject[]{deserialiseValue(), deserialiseValue()}));
                    }

                    DeserialisedObject[] o = list.toArray(new DeserialisedObject[0]);
                    return new DeserialisedObject(HASHTABLE, o);
                }

                case 0x19:  // type
                    return new DeserialisedObject(TYPE, readType());

                case 0x1b:  // Unit
                    return new DeserialisedObject(UNIT, new Unit(readDouble(), (byte) readInt32()));

                case 0x1c:  // Unit.Empty
                    return new DeserialisedObject(UNIT, new Unit(0, (byte) 0));

                case 0x1e:  // IndexedString
                case 0x1f:
                    return new DeserialisedObject(STRING, readIndexedString(token));

                case 0x28:  // object converted to string
                {
                    Object type = readType();
                    String text = readString();
                    if (type != null)
                    {
                        return new DeserialisedObject(
                                SERIALISED_OBJECT,
                                new SerialisedObject(text)
                        );
                    }
                    else
                    {
                        return new DeserialisedObject(NULL, null);
                    }
                }

                case 0x32:  // serialised object
                {
                    int count = readEncodedInt32();
                    byte[] b = new byte[count];
                    //noinspection ResultOfMethodCallIgnored
                    is.read(b, 0, count);
                    return new DeserialisedObject(SERIALISED_OBJECT, new SerialisedObject(helpers.bytesToString(b)));
                }

                case 0x3c:  // array containing a lot of nulls
                {
                    Object type = readType();
                    int length = readEncodedInt32();
                    int numNonNulls = readEncodedInt32();
                    if (numNonNulls > length)
                    {
                        throw new Exception("InvalidSerializedData");
                    }

                    DeserialisedObject[] array = new DeserialisedObject[length];
                    for (int i = 0; i < length; i++)
                    {
                        array[i] = new DeserialisedObject(NULL, null);
                    }

                    for (int i = 0; i < numNonNulls && !errorOccurred; i++)
                    {
                        int index = readEncodedInt32();
                        if (index >= length || index < 0)
                        {
                            throw new Exception("InvalidSerializedData");
                        }

                        array[index] = deserialiseValue();
                    }

                    return new DeserialisedObject(ARRAY, new DeserialisedArray(type, array));
                }

                case 0x64:  // null
                    return new DeserialisedObject(NULL, null);

                case 0x65:  // empty string
                    return new DeserialisedObject(STRING, "");

                case 0x66:  // zero
                    return new DeserialisedObject(INT32, 0);

                case 0x67:  // bool - true
                    return new DeserialisedObject(BOOLEAN, true);

                case 0x68:  // bool - false
                    return new DeserialisedObject(BOOLEAN, false);

                default:
                    throw new Exception("Unrecognized token: " + token + "  [0x" + Integer.toString(token, 16) + "]");
            }
        } catch (Exception e)
        {
            errorOccurred = true;
            return new DeserialisedObject(ERROR, null);
        }
    }

    //
    // methods to read data from stream
    //
    private int readByte() throws Exception
    {
        int i = is.read();

        if (i == -1)
        {
            throw new Exception("End of stream");
        }

        return i;
    }

    public int readInt16() throws Exception
    {
        fillBuffer(2);
        return (short) (buffer[0] | (buffer[1] << 8));
    }

    private int readInt32() throws Exception
    {
        fillBuffer(4);
        return (((buffer[0] | (buffer[1] << 8)) | (buffer[2] << 0x10)) | (buffer[3] << 0x18));
    }

    private int readEncodedInt32() throws Exception
    {
        return read7BitEncodedInt();
    }

    private int read7BitEncodedInt() throws Exception
    {
        byte num3;
        int num = 0;
        int num2 = 0;
        do
        {
            if (num2 == 0x23)
            {
                throw new Exception("Invalid Format_Bad7BitInt32");
            }

            num3 = (byte) readByte();
            num |= (num3 & 0x7f) << num2;
            num2 += 7;
        }
        while ((num3 & 0x80) != 0);

        return num;
    }

    @SuppressWarnings("IntegerMultiplicationImplicitCastToLong")
    private long readInt64() throws Exception
    {
        fillBuffer(8);
        long num = 0xffffffffL & (((buffer[0] | (buffer[1] << 8)) | (buffer[2] << 0x10)) | (buffer[3] << 0x18));
        long num2 = 0xffffffffL & (((buffer[4] | (buffer[5] << 8)) | (buffer[6] << 0x10)) | (buffer[7] << 0x18));
        return (num2 << 0x20) | num;
    }

    private double readDouble() throws Exception
    {
        return Double.longBitsToDouble(readInt64());
    }

    private float readFloat() throws Exception
    {
        fillBuffer(4);
        int num = (((buffer[0] | (buffer[1] << 8)) | (buffer[2] << 0x10)) | (buffer[3] << 0x18));
        return Float.intBitsToFloat(num);
    }

    private String readString() throws Exception
    {
        int capacity = read7BitEncodedInt();
        if (capacity < 0)
        {
            throw new Exception("Invalid IO.IO_InvalidStringLen_Len");
        }

        if (capacity == 0)
        {
            return "";
        }

        byte[] b = new byte[capacity];
        //noinspection ResultOfMethodCallIgnored
        is.read(b, 0, capacity);

        return helpers.bytesToString(b);
    }

    private Object readType() throws Exception      // returns a Class or AspDotNetType
    {
        int num = readByte();
        if (num == 0x2b)    // use index into typeList
        {
            int num2 = readEncodedInt32();
            return typeList.get(num2);
        }

        // use named type
        String name = readString();
        Type type = new Type(name);
        addDeserialisationTypeReference(type);
        return type;
    }

    String readIndexedString(int token) throws Exception
    {
        if (token == 0x1f)
        {
            int index = readByte();
            return stringList[index];
        }
        String s = readString();
        addDeserialisationStringReference(s);
        return s;
    }


    // 
    // helper methods
    //
    private void addDeserialisationTypeReference(Object type)
    {
        typeList.add(type);
    }

    private void addDeserialisationStringReference(String s)
    {
        if (stringTableCount == 0xff)
        {
            stringTableCount = 0;
        }
        stringList[stringTableCount] = s;
        stringTableCount++;
    }

    private void fillBuffer(int numBytes) throws Exception
    {
        int offset = 0;
        do
        {
            buffer[offset++] = readByte();
        }
        while (offset < numBytes);
    }
}
