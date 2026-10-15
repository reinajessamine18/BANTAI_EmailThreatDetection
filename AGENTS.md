# BANTAI — Project Instructions

## 1. Project Overview

BANTAI is an AI-powered email threat detection and analysis system developed as an academic research project.

Formal research title:

**XGBoost-Based Email Threat Detection and Analysis Engine using Explainability Framework**

The system is designed to analyze email content and metadata, identify potentially malicious or phishing emails, assign a threat score and risk classification, and provide explainable analysis to users.

The project is developed using a hybrid Agile Scrum and CRISP-DM methodology.

---

## 2. Research Methodology

The project follows:

- Agile Scrum
- CRISP-DM

CRISP-DM stages:

1. Business Understanding
2. Data Understanding
3. Data Preparation
4. Modeling
5. Evaluation
6. Deployment

Do not silently replace or modify the approved research methodology.

If a proposed implementation would significantly change the research methodology, system architecture, ML approach, evaluation methodology, or research objectives, identify the change and explain its implications before implementing it.

---

## 3. Core System Architecture

The intended system architecture consists of:

### Frontend / Presentation Layer

- React
- Vite
- Tailwind CSS
- Chart.js

The frontend is responsible for user interaction, email submission, displaying threat analysis results, threat history, settings, and visualizations.

### Backend / API Layer

- Python
- FastAPI
- Uvicorn
- Pydantic

The backend is responsible for API requests, input validation, email processing, communication with the ML pipeline, and returning structured results to the frontend.

### Email Processing

The system may use:

- Python `email` library
- BeautifulSoup4 for HTML processing
- Regular expressions or appropriate parsers for URL extraction

### Machine Learning Layer

The primary machine learning classifier is:

**XGBoost**

The primary explainability framework is:

**SHAP using TreeExplainer**

### Data Processing

The project may use:

- Pandas
- scikit-learn

for data processing, preprocessing, feature engineering, and numerical representation.

### Persistence / Audit Layer

The development system may use:

- SQLite
- SQLAlchemy

Persistent records should focus on scan metadata, results, and audit information rather than unnecessarily storing sensitive email body content.

---

## 4. Research Integrity

Never fabricate or assume experimental results.

Do not invent:

- Accuracy
- Precision
- Recall
- F1-score
- ROC-AUC
- Confusion matrices
- Inference time
- Dataset statistics
- Model performance
- SHAP findings
- User evaluation results

Only report results that were actually generated through the appropriate experiment, test, or evaluation.

Clearly distinguish between:

- Requirements stated in the research
- Implementation decisions
- Assumptions
- Experimental results

If a requirement or implementation detail is not specified in the research documentation, identify it as an open decision rather than presenting an invented value as a research requirement.

---

## 5. Do Not Change the Research Direction Silently

The following are core research components:

- XGBoost classification
- SHAP-based explainability
- Email threat detection
- Threat scoring
- Explainable analysis
- Hybrid Agile + CRISP-DM methodology

Do not replace these with another technology or methodology without discussion.

Alternative algorithms or techniques may be implemented as baselines or experiments when appropriate, but they must not silently replace the primary research approach.

---

## 6. Data Integrity and Security

Treat email data as potentially sensitive.

Do not expose or permanently store sensitive email body content unless explicitly required by the approved system design.

Do not hardcode:

- API keys
- passwords
- authentication tokens
- database credentials
- private keys
- other secrets

Use environment variables or appropriate secret-management mechanisms.

Do not commit `.env` files or other files containing secrets.

---

## 7. Data Leakage Prevention

Machine learning implementations must avoid data leakage.

When preprocessing or transforming data:

- Fit learned preprocessing operations using training data only.
- Apply fitted transformations to validation and test data.
- Keep the final test set isolated until final evaluation.
- Do not repeatedly use test-set performance to make model decisions.

If a proposed implementation could introduce leakage, identify the issue before proceeding.

---

## 8. Reproducibility

Important development and experimental decisions should be documented.

When applicable, record:

- Dataset source
- Dataset version
- Feature definitions
- Preprocessing procedures
- Train/validation/test split
- Random seed
- Model parameters
- Hyperparameter search settings
- Evaluation metrics
- Python version
- Package versions
- Relevant hardware information

Experiments should be reproducible whenever reasonably possible.

---

## 9. Code Quality

Prefer:

- Readable code
- Simple implementations
- Clear naming
- Modular components
- Small, focused functions
- Appropriate error handling
- Reusable utilities
- Tests for important functionality

Avoid:

- Unnecessary abstractions
- Unrelated refactoring
- Premature optimization
- Duplicate logic
- Hardcoded secrets
- Hardcoded machine-specific paths
- Large rewrites when a small change is sufficient

Do not modify unrelated parts of the project while implementing a requested feature.

---

## 10. Team Development

BANTAI is a collaborative project.

Respect existing work created by other team members.

Before modifying another team's component:

1. Inspect the existing implementation.
2. Understand how it connects to the rest of the system.
3. Avoid unnecessary structural changes.
4. Preserve existing functionality unless the change is intentional.
5. Explain significant compatibility concerns.

Do not overwrite or delete another team member's work without a clear reason.

---

## 11. API and Component Boundaries

Maintain clear separation between:

- Frontend presentation
- Backend/API logic
- Email parsing
- Feature engineering
- Machine learning inference
- Explainability
- Database/audit functionality

The frontend should communicate with the backend through defined API interfaces.

Do not duplicate machine learning logic inside the frontend.

Do not tightly couple unrelated components without a clear architectural reason.

---

## 12. Testing

After implementing a change:

1. Run the relevant tests.
2. Run relevant linting or type checks when available.
3. Run the affected application component when practical.
4. Check for errors.
5. Report what was actually tested.

Never claim that a feature works if it has not been tested.

---

## 13. Git and Repository Practices

Do not commit:

- `.env` files
- API keys
- Passwords
- Authentication tokens
- Large temporary files
- Generated caches
- Python virtual environments
- `node_modules`
- Temporary logs

Use `.gitignore` for files that should remain local.

Keep commits focused and descriptive.

Do not rewrite shared Git history unless explicitly agreed upon by the team.

Do not force-push to shared branches without team agreement.

---

## 14. Handling Ambiguous Requirements

The research documentation may not specify every implementation detail.

When a requirement is ambiguous or missing:

1. Identify what is unspecified.
2. Do not silently invent a requirement.
3. Explain reasonable implementation options.
4. Recommend an option when appropriate.
5. Clearly label the choice as an implementation decision or assumption.

Examples include:

- Dataset source
- Exact feature list
- Data split ratio
- Missing-value strategy
- Class imbalance strategy
- XGBoost hyperparameters
- Classification thresholds
- Baseline models
- Database implementation details

---

## 15. Development Behavior

When working on BANTAI:

- Inspect before modifying.
- Follow the existing project structure.
- Preserve the approved research direction.
- Make incremental changes.
- Avoid unrelated modifications.
- Protect sensitive information.
- Test changes before declaring them complete.
- Keep important assumptions explicit.
- Never fabricate research results.

When a request is clear and low-risk, proceed with implementation.

When a request would significantly change the research methodology or system architecture, explain the impact before making the change.
