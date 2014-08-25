<%page args="prefix = 'label'"/>
<%docstring>
Returns a new unique label with a given prefix.

Args:
  prefix (str): The string to prefix the label with
</%docstring>
<%!
    label_num = 0
%>
<%
   global label_num
   label_num += 1
%>
${prefix}_${label_num}
