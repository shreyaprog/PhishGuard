# Viva Questions and Answers

1. **What is phishing?** A deceptive attempt to make a person disclose information, approve an action, or install something by impersonating a trusted party.
2. **Why analyse URLs?** Hostname and URL structure can reveal indicators useful for triage, though they cannot prove intent.
3. **What does PhishGuard do?** It extracts URL features, runs explainable local rules, optionally predicts with a trained model, and records an assessment.
4. **Does PhishGuard visit submitted URLs?** No. Parsing and feature extraction are local and do not make network requests to the URL.
5. **Why is HTTPS not proof of legitimacy?** HTTPS encrypts a connection to a host; it does not establish that the host is trustworthy.
6. **What is a misleading subdomain?** A hostname may place a brand-like word in a subdomain while the registrable domain belongs to another party.
7. **What is a feature?** A measurable input derived from a URL, such as hostname length or whether the host is an IP address.
8. **What is a rule engine?** A deterministic set of checks that reports specific URL indicators and their evidence.
9. **Why combine rules and ML?** ML can identify patterns in labelled data while rules provide direct, reviewable evidence; neither is conclusive.
10. **What does the model probability mean?** It is the classifier's estimated score for its phishing class, not necessarily a calibrated real-world probability.
11. **What is the overall risk score?** A documented heuristic combining a model output, when available, with grouped rule signals; it is not a probability.
12. **What is precision?** Among URLs flagged by the model, the fraction that are labelled phishing in the evaluation set.
13. **What is recall?** Among phishing-labelled examples in the evaluation set, the fraction the model flagged.
14. **Why is recall important?** Low recall means more phishing-labelled examples are missed.
15. **Why is precision important?** Low precision means more legitimate examples are incorrectly flagged, creating unnecessary disruption.
16. **What is a false positive?** A legitimate-labelled example incorrectly predicted as phishing.
17. **What is a false negative?** A phishing-labelled example incorrectly predicted as legitimate.
18. **What does a confusion matrix show?** Counts of true and false predictions for each class, enabling inspection of different error types.
19. **Why report F1?** It combines precision and recall as a harmonic mean, though it does not replace reviewing both values.
20. **What is ROC-AUC?** A threshold-independent summary of how well scores rank positive above negative examples; it does not select a safe operational threshold.
21. **What is class imbalance?** Unequal numbers of examples across labels, which can make accuracy misleading.
22. **What is overfitting?** When a model learns patterns specific to its training examples and performs poorly on new data.
23. **What is data leakage?** Information from the test set or correlated examples improperly influences training or evaluation, inflating results.
24. **Why can a random URL split leak domain patterns?** URLs from the same domain or campaign may appear in both train and test sets.
25. **What is domain-grouped evaluation?** Assigning all examples from a domain to only one partition to better test generalisation to unseen domains.
26. **What is explainable AI in this project?** Rule findings show human-readable evidence, and the linear model can show per-feature contributions for one prediction.
27. **Are feature contributions causal explanations?** No. They describe how fitted model coefficients contribute mathematically to a prediction.
28. **What is IAM?** Identity and Access Management controls which identities may perform which actions on cloud resources.
29. **Why use least privilege?** It limits the permissions available to an identity if its credentials are misused or compromised.
30. **How does MFA help?** It adds an authentication factor, making a stolen password alone less sufficient for access.
31. **What is the cloud shared responsibility model?** The provider secures the underlying cloud infrastructure; customers secure their identities, data, configurations and workloads, with exact boundaries depending on the service.
32. **Why are audit logs useful?** They help investigate activity, detect suspicious access and support response actions.
33. **What should a user do after entering credentials on a suspicious site?** Change the password through the official service, revoke active sessions where possible, notify the security team, and review account activity.
34. **Does a no-match threat-intelligence lookup prove a site is safe?** No. It only means no exact match was found in the local indicators.
35. **What are the main project limitations?** URL-only analysis, dataset freshness and bias, false positives/negatives, model generalisation, and a lack of live reputation context.
