---
name: Feature Request
about: Suggest an enhancement or new feature for NetGuard
title: '[Feature Request] '
labels: enhancement
assignees: ''
---

# Feature Request

Thank you for contributing to NetGuard! Please use this template to propose a new feature or enhancement for the project. Provide as much detail as possible to help the maintainers understand and evaluate your suggestion.

## Problem Description
Describe the problem or limitation that this feature addresses. Be clear and concise, explaining why this is an issue or opportunity for improvement.  
*Example*: "Current rule definitions are limited to HTTP protocols, which restricts detection capabilities for other common protocols like DNS."

## Proposed Solution
Provide a detailed description of the feature or enhancement you would like to see implemented. Include:
- What the feature should do
- How it would benefit users or the project
- Any specific functionality or behavior expected  
*Example*: "Implement a DNS packet parser to support detection of DNS-based attacks, such as tunneling, with corresponding rules in `rules/protocols/dns.rules`."

## Alternatives Considered
Describe any alternative solutions or approaches you have considered. Explain why these alternatives are less desirable or why your proposed solution is preferred.  
*Example*: "An alternative is to rely on external tools for DNS analysis, but integrating DNS parsing directly into NetGuard would improve performance and maintainability."

## Additional Context
Include any additional information, such as:
- Use cases or scenarios where the feature would be valuable
- References to similar features in other projects (e.g., Snort, Suricata)
- Mockups, diagrams, or screenshots (if applicable)
- Technical considerations (e.g., impact on performance or compatibility)  

*Example*: "This feature would enable NetGuard to detect DNS tunneling attacks, which are increasingly common in enterprise networks. See [Snort DNS rules](https://www.snort.org/) for inspiration."

## Related Issues
If this feature relates to existing issues, reference them here (e.g., `#123`).

---

**Note**: Before submitting, please check the [Contribution Guidelines](CONTRIBUTION.md) and [Development Guide](DEVELOPMENT.md) for details on how to propose and implement features. For questions, contact the maintainers at [contact@out-sec.org](mailto:contact@out-sec.org).