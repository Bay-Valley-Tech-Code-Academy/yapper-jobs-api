# API
  `<String>` max length is 255 unless otherwise (noted)
  
  `<Date>` in the format "YYYY-MM[-DD]"
  
  `<JSON>` expect no nesting unless otherwise (noted)

## Endpoint: post /register/seeker
   Params: none

   Expects:

      {
        firstName: <String>,
        lastName: <String>,
        pass: <String>,
        email: <String>
      }

   Responses:

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

## Endpoint: post /register/employer
   Params: none

   Expects:

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

   Responses:

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

## Endpoint: post /login/seeker
   Params: none

   Expects:

    {
      email: <String>,
      pass: <String>
    }

   Responses:

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

## Endpoint: post /login/employer
   Params: none

   Expects:

    {
      email: <String>,
      pass: <String>
    }

   Responses:

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

## Endpoint: post /job/:job_id/get
   Params: :job_id

   Expects: none

   Responses:

    {
      success: true,
      job: {
        title:  <String>,
        company:  <String>,
        city:  <String>,
        state:  <String>,
        is_remote: <boolean>,
        industry:  <String>,
        website:  <String>,
        experience_level:  <String>,
        employment_type:  <String>,
        company_size:  <String>,
        salary_low: <number>,
        salary_high: <number>,
        benefits: <JSON || null>,
        certifications: <JSON || null>,
        job_description:  <String>,
        questions: <JSON || null>,
        date_created: <Date>,
        expires: <boolean>,
        date_expires: <Date || null>
      }
    }

    {
      success: false,
      error: <String>
    }

## Endpoint: post /job/add
   Params: none

   Expects:

    {
      title: <String>,
      city: <String>,
      state: <String(|2|)>,
      isRemote: <boolean>,
      experienceLevel: <String || null>,
      employmentType: <String>,
      companySize: <String>,
      salaryLow: <number || null>,
      salaryHigh: <number || null>,
      benefits: <JSON{Strings} || null>,
      certifications: <JSON{Strings} || null>,
      jobDescription: <String(600)>,
      questions: <JSON{Strings} || null>, //max 15
      expDate: <Date || null>
    }

   Responses:

    {
      success: true,
      jobId: <number>
    }

    {
      success: false,
      error: <String>
    }

## Endpoint: post /resume/add
   Params: none

   Expects:

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

   Responses:

    {
      success: true,
      jobId: <number>
    }

    {
      success: false,
      error: <String>
    }

## Endpoint: get /resume
   Params: none

   Expects: none

   Responses:

    {
      success: true,
      seeker: <JSON{
        first_name: <String>,
        last_name: <String>,
        email: <String>,
        summary: <String(600)>
      },
      education: <JSON array || null>,
      experience: <JSON array || null>,
      skill: <JSON array || null>,
      link: <JSON array || null>,
      publication: <JSON array || null>
    }

    {
      success: false,
      error: <String>
    }

## Endpoint: post /job/apply/:job_id/submit
   Params: :job_id

   Expects:

    {
      answers: <JSON{Strings} || null>  //max 15
    }

   Responses:

    {
      success: true,
      message: 'application submitted'
    }

    {
      success: false,
      error: <String>
    }

## Endpoint: get /job/applied
   Params: none

   Expects: none

   Responses:

    {
      success: true,
      title: <String>,
      date_applied: <Date>,
      questions: <JSON>,
      answers: <JSON>
    }

    {
      success: false,
      error: <String>
    }

## Endpoint: get /job/applications
   Params: none

   Expects: none

   Responses:

    {
      success: true,
      apps: <JSON array(2500)>
    }

    {
      success: false,
      error: <String>
    }

## Endpoint: get /job/applications/resume
   Query: email: seeker email

   Expects: none

   Responses:

    {
      success: true,
      resume_url: <String(2048)>
    }

    {
      success: true,
      seeker: <JSON{
        first_name: <String>,
        last_name: <String>,
        email: <String>,
        summary: <String(600)>
      }>,
      education: <JSON array || null>,
      experience: <JSON array || null>,
      skill: <JSON array || null>,
      link: <JSON array || null>,
      publication: <JSON array || null>
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

# JWT
  ## Login JWT contents

    {
      user_id: <String>,
      email: <String>,
      company: <String || null>,
      type: <String>, //user type
      exp: <number>
    }

# Log
  ## Format

    <timestamp> | [status] | <source> | [success || error || info] | [reason] | <attempt + ip || ip>\n

  status should only be used when logging response to request.
  
  reason should only be used if an error occurs.

  ## Examples

    writer.write(`${setTimestamp(newTime)} | status: 400 | source: /login/seeker | error: "Login failed" | reason: "User not found" | attempt: ${email}@${req.socket.remoteAddress}\n`);

    writer.write(`${setTimestamp(time)} | | source: server | info: server started | | port: ${port}\n`);