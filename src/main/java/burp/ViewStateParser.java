package burp;

import burp.viewstate.Deserialiser;

import static java.util.Arrays.copyOfRange;

class ViewStateParser
{
    private static final String VIEW_STATE_PARAMETER_NAME = "__VIEWSTATE";
    private static final byte[] VIEW_STATE_INPUT_NAME = new byte[] {'_', '_', 'V', 'I', 'E', 'W', 'S', 'T', 'A', 'T', 'E'};
    private static final byte[] FORM_OPEN_TAG = new byte[] {'<', 'f', 'o', 'r', 'm'};
    private static final byte[] FORM_CLOSE_TAG = new byte[] {'<', '/', 'f', 'o', 'r', 'm'};
    private static final byte[] INPUT_TAG = new byte[] {'<', 'i', 'n', 'p', 'u', 't'};
    private static final byte[] TAG_END = new byte[] {'>'};
    private static final byte[] NAME_ATTR = new byte[] {'n', 'a', 'm', 'e', '='};
    private static final byte[] VALUE_ATTR = new byte[] {'v', 'a', 'l', 'u', 'e', '='};

    private final IExtensionHelpers helpers;

    ViewStateParser(IExtensionHelpers helpers)
    {
        this.helpers = helpers;
    }

    ViewStateInfo parseRequest(IRequestInfo info)
    {
        IParameter vsParam = info.getParameters().stream().filter(this::isViewStateParameter).findFirst().orElse(null);

        if (vsParam == null)
        {
            return null;
        }

        byte[] value = helpers.stringToBytes(vsParam.getValue());
        byte[] decodedContent = info.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED ? helpers.urlDecode(value) : value;

        return new ViewStateInfo(Deserialiser.deserialise(decodedContent, helpers), vsParam.getValueStart(), vsParam.getValueEnd());
    }

    private boolean isViewStateParameter(IParameter param)
    {
        return param.getName().equals(VIEW_STATE_PARAMETER_NAME);
    }

    ViewStateInfo parseResponse(IResponseInfo info, byte[] content)
    {
        int valueStart = findViewStateFieldValueStart(info, content);

        if (valueStart == -1)
        {
            return null;
        }

        int valueEnd = findViewStateFieldValueEnd(content, valueStart);

        if (valueEnd == -1)
        {
            return null;
        }

        byte[] value = copyOfRange(content, valueStart, valueEnd);

        return new ViewStateInfo(Deserialiser.deserialise(value, helpers), valueStart, valueEnd);
    }

    boolean hasViewStateField(IResponseInfo responseInfo, byte[] content)
    {
        return findViewStateFieldValueStart(responseInfo, content) > 0;
    }

    private int findViewStateFieldValueStart(IResponseInfo responseInfo, byte[] content)
    {
        if (!"HTML".equals(responseInfo.getInferredMimeType()))
        {
            return -1;
        }

        int formStart = helpers.indexOf(content, FORM_OPEN_TAG, false, responseInfo.getBodyOffset(), content.length);

        if (formStart == -1)
        {
            return -1;
        }

        int formEnd = helpers.indexOf(content, FORM_CLOSE_TAG, false, formStart, content.length);

        if (formEnd == -1)
        {
            formEnd = content.length;
        }

        int position = formStart + FORM_OPEN_TAG.length;

        while (position < formEnd)
        {
            int inputStart = helpers.indexOf(content, INPUT_TAG, false, position, formEnd);

            if (inputStart == -1)
            {
                break;
            }

            int inputPosition = inputStart + INPUT_TAG.length;

            int inputTagEnd = helpers.indexOf(content, TAG_END, false, inputPosition, formEnd);

            if (inputTagEnd == -1)
            {
                inputTagEnd = formEnd;
            }

            int nameStart = helpers.indexOf(content, NAME_ATTR, false, inputPosition, inputTagEnd);

            if (nameStart != -1)
            {
                int pos = nameStart + NAME_ATTR.length + 1;
                if (content[pos] == '\'' || content[pos] == '"')
                {
                    pos++;
                }

                if (helpers.indexOf(content, VIEW_STATE_INPUT_NAME, false, pos, inputTagEnd) != -1)
                {
                    pos += VIEW_STATE_INPUT_NAME.length + 1;
                    pos = helpers.indexOf(content, VALUE_ATTR, false, pos, inputTagEnd);

                    if (pos == -1)
                    {
                        return inputTagEnd + 1;
                    }

                    pos += VALUE_ATTR.length;

                    if (content[pos] == '\'' || content[pos] == '"')
                    {
                        pos++;
                    }

                    return pos;
                }
            }

            position = inputTagEnd + TAG_END.length;
        }

        return -1;
    }

    private static int findViewStateFieldValueEnd(byte[] content, int viewStateFieldValueStart)
    {
        for (int i = viewStateFieldValueStart; i < content.length; i++)
        {
            byte b = content[i];

            if (b == '\'' || b == '"' || b == ' ' || b == '<' || b == '>')
            {
                return i;
            }
        }

        return content.length;
    }
}
