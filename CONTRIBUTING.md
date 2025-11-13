# Contributing

First of all, we appreciate you reading this before continuing to any other tasks.

Filter lists are usually provide the full experience when it's used with content blockers such as uBlock Origin and Ghostery.
However, there are important things to mention for filter lists to work well with DNS blockers and other systems at the time.

## Prioritising features and having less performance impact

Please, keep the performance impact in your mind when writing filters.

For an instance, network filtering should be more preferred rather than complicated cosmetic filtering features such as a script injection.
Network filtering has much less performance impact, especially arise of decalartive network requests API with the manifest version 3 transition.

The below are **avoided** if possible:

- URL pattern involving regular expression
- `$replace` modifier (only can be used by platforms supporting manifest version 2)
- XPath or extended selectors (using `:has` is still encouraged as they're supported by modern browsers)
- `trusted-` prefixed scriptable snippets
- Any other platform specific features

### When to use `$3p`?

There are some confusions regarding the third party modifier when writing network filtering.
Depending on the case, it might not impact so much on browsing experience.

However, it's an important hint for DNS blockers or other types of blockers working with limited information.
We can assume that filters with the third party modifier should still remain accessible when a user try to access.
For an instance, you don't use the third party modifier in case of a malicious hostname which is not expected to be visited by users.

A great example would be `analytics.google.com`, which hosts tracking scripts for other websites.
However, we would put `$3p` to the hostname as we still expect the website to be accessible.
You may argue that casual users don't need to access that website but it's a preference when you generate a DNS block list.
The user should include all filters with the third party modifier if they want a stronger filtering feature.
