<%!
    label_num = 0
    last_labels = {}
%>

<%def name="label(prefix = 'label')">
<%docstring>
Returns a new unique label with a given prefix.

Args:
  prefix (str): The string to prefix the label with
</%docstring>
<%
   global label_num, last_label
   cur = prefix + '_' + str(label_num)
   last_labels[prefix] = cur
   label_num += 1
%>
${cur}
</%def>

<%def name="lastlabel(prefix = 'label')">
<%docstring>Returns the last created label with a given prefix.</%docstring>
${last_labels.get(prefix, 'label_not_found')}
</%def>
