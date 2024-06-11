# API
  `<String>` max length is 255 unless otherwise (noted)
  
  `<Date>` in the format "YYYY-MM[-DD]"
  
  `<JSON>` expect no nesting unless otherwise (noted)

## Endpoint: /register/seeker
  ### Expects:
    {
      firstName: <String>,
      lastName: <String>,
      pass: <String>,
      email: <String>
    }
  ### Responses:
    {
      success: true,
      firstName: <String>,
      lastName: <String>,
      email: <String>,
      jwt: <String(null)>
    }

    {
      success: false,
      error: <String>
    }

## Endpoint: /register/employer
  ### Expects:
    {
      firstName: <String>,
      lastName: <String>,
      pass: <String>,
      email: <String>,
      mobile: <String(15)>,
      company: <String>,
      website: <String(2047)>,
      industry: <String>
    }
  ### Responses:
    {
      success: true,
      firstName: <String>,
      lastName: <String>,
      email: <String>,
      company: <String>,
      jwt: <String(null)>
    }

    {
      success: false,
      error: <String>
    }

## Endpoint: /login/seeker
  ### Expects:
    {
      email: <String>,
      pass: <String>
    }
  ### Responses:
    {
      success: true,
      firstName: <String>,
      lastName: <String>,
      email: <String>,
      jwt: <String(null)>
    }

    {
      success: false,
      error: <String>
    }

## Endpoint: /login/employer
  ### Expects:
    {
      email: <String>,
      pass: <String>
    }
  ### Responses:
    {
      success: true,
      firstName: <String>,
      lastName: <String>,
      email: <String>,
      company: <String>,
      jwt: <String(null)>
    }

    {
      success: false,
      error: <String>
    }

## Endpoint: /job/add
  ### Expects:
    {
      title: <String>,
      city: <String>,
      state: <String(|2|)>,
      isRemote: <boolean>,
      experienceLevel: <String || null>,
      employmentType: <String>,
      companySize: <number || null>,
      salaryLow: <number || null>,
      salaryHigh: <number || null>,
      benefits: <JSON{Strings} || null>,
      certifications: <JSON{Strings} || null>,
      jobDescription: <String(600)>,
      questions: <JSON{Strings} || null>,
      expDate: <Date || null>
    }
  ### Responses:
    {
      success: true,
      jobId: <number>
    }

    {
      success: false,
      error: <String>
    }

## Endpoint: /resume/add
  ### Expects:
    {
      summary: <String(600)>,
      education: <JSON(2): {
        key: {
          institutionName: <String>,
          educationLevel: <String>,
          educationField: <String>,
          dateStart: <Date>,
          dateEnd: <Date || null>,
          present: <boolean>
        }
      } || null>,
      experience: <JSON(3): {
        key: {
          jobTitle: <String>,
          companyName: <String>,
          address: <String>,
          city: <String>,
          state: String(|2|)>,
          dateStart: <Date>,
          dateEnd: <Date || null>,
          present: <boolean>,
          remote: <boolean>,
          jobDescription: <String || null>
        }
      } || null>,
      skill: <JSON(25): {
        key: {
          skillName: <String>,
          skillYears: <number>
        }
      } || null>,
      link: <JSON(5): {
        key: {
          linkName: <String>,
          linkUrl: <String(2047)>
        }
      } || null>,
      publication: <JSON(5): {
        key: {
          pubName: <String>,
          pubUrl: <String(2047)>,
          pubDate: <Date>,
          pubSummary: <String(600)>
        }
      } || null>
    }
  ### Responses:
    {
      success: true,
      jobId: <number>
    }

    {
      success: false,
      error: <String>
    }

# API Examples
  ## Multiple Entries for Endpoint: /resume/add
    "education": {
        "1": {
            "institutionName": "Example Community College",
            "educationLevel": "college",
            "educationField": "Example",
            "dateStart": "2012-08",
            "dateEnd": "2014-05",
            "present": false
        },
        "2": {
            "institutionName": "Example University",
            "educationLevel": "College",
            "educationField": "Example",
            "dateStart": "2014-09",
            "dateEnd": "2018-06",
            "present": false
        }
    }


## JWT contents
  user_id
  email
  company //null if not employer
  type    //user type
  exp
