# Web Authentication Working Group

Contributions to this repository are intended to become part of Recommendation-track documents 
governed by the [W3C Patent Policy](http://www.w3.org/Consortium/Patent-Policy-20040205/) and
[Document License](http://www.w3.org/Consortium/Legal/copyright-documents). To contribute, you must 
either participate in the relevant W3C Working Group or make a [non-member patent licensing
 commitment](https://www.w3.org/policies/process/#contributor-license).

If you are a non-member but would like to contribute, simply open a Pull Request. 
The IPR bot will flag any need for commitment; get in touch with the
[Staff Contact](https://www.w3.org/groups/wg/webauthn/) to confirm it.

If you are not the sole contributor to a contribution (pull request), please identify all 
contributors in the pull request's body or in subsequent comments.

 To add a contributor (other than yourself, that's automatic), mark them one per line as follows:

 ```
 +@github_username
 ```

 If you added a contributor by mistake, you can remove them in a comment with:

 ```
 -@github_username
 ```

 If you are making a pull request on behalf of someone else but you had no part in designing the 
 feature, you can remove yourself with the above syntax.


## Editorial conventions

When editing the spec, please follow these editorial conventions.


### Text macros

Where appropriate, use the
[text macros defined near the beginning of the document](https://github.com/w3c/webauthn/blob/93193a1dcfddf6a6daa4726fafa4f556bff203ca/index.bs#L51-L60).
For example, use `[TRUE]` to render `<code>true</code>`
and use `[=[RP]=]` to render a linked reference to the term "Relying Party".


### Semantic line breaks

Use [semantic line breaks][sembr].
To summarize, this means adding line breaks at semantically meaningful points,
such as after punctuation, before subordinate clauses, etc.
This makes changes easier to review and helps automatic conflict resolution,
as small changes are more likely to affect only one or a few lines
rather than an entire paragraph.
For more examples and rationale, see: https://github.com/w3c/webauthn/issues/2045.

Use semantic line breaks along these additional guidelines:

- Do not change existing text just for the sake of introducing semantic line breaks.
- When changing text that is not formatted with semantic line breaks,
  reformat changing lines to use semantic line breaks.
  Do not reformat unchanged neighboring lines to use semantic line breaks unless it's very few lines,
  or it otherwise helps readability,
  or it otherwise seems like a good idea.
- When changing text that already uses semantic line breaks,
  add and remove semantic line breaks as appropriate but only as needed for the change.
  Do not break or join lines that would otherwise remain unchanged.
- When adding new text, use semantic line breaks.
- Take the [Semantic Line Breaks specification][sembr] as a set of guidelines, not a rigid set of rules.
  If a contributor proposes changes that clearly do not use semantic line breaks,
  inform or remind them of the convention and ask them to reformat,
  but respect their choice of where to place line breaks and do not "bikeshed" the details.
  The goal is to make the text easier to work with, not to enforce a style.
- We do not set a hard line length limit, because of how much indentation and markup syntax we use.
  As a rule of thumb, aim for about 100 characters per line,
  or about 80 characters excluding indentation.
  Use good judgement of where to draw the line in each case.

[sembr]: https://sembr.org/
