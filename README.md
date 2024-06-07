+ Endpoint: /register/seeker
  - Expects: `{firstName: <String>, lastName: <String>, pass: <String>, email: <String>}`
  - Responses:
    - `{success: true, firstName: <String>, lastName: <String>, email: <String>, jwt: <String>}`
    - `{success: false, error: <String>}`

+ Endpoint: /register/employer
  - Expects: `{firstName: <String>, lastName: <String>, pass: <String>, email: <String>, mobile: <String>, company: <String>, website: <String>, industry: <String>}`
  - Responses:
    - `{success: true, firstName: <String>, lastName: <String>, email: <String>, company: <String>, jwt: <String>}`
    - `{success: false, error: <String>}`

+ Endpoint: /login/seeker
  - Expects: `{email: <String>, pass: <String>}`
  - Responses:
    - `{success: true, firstName: <String>, lastName: <String>, email: <String>, jwt: <String>}`
    - `{success: false, error: <String>}`

+ Endpoint: /login/employer
  - Expects: `{email: <String>, pass: <String>}`
  - Responses:
    - `{success: true, firstName: <String>, lastName: <String>, email: <String>, company: <String>, jwt: <String>}`
    - `{success: false, error: <String>}`

+ Endpoint: /add-job
  - Expects: `{title: <String>, city: <String>, state: <String>, zip: <number>, experienceLevel: <String || null>, employmentType: <String>, companySize: <number || null>, salaryLow: <number || null>, salaryHigh: <number || null>, benefits: <JSON || null>, certifications: <JSON || null>, jobDescription: <String>, questions: <JSON || null>}`
  - Responses:
    - `{success: true, jobId: <number>}`
    - `{success: false, error: <String>}`

+ JWT contents
  - user_id
  - email
  - company //null if not employer
  - type    //user type
  - exp
