const fetch = require("node-fetch");
const mysql = require("mysql2/promise");

const fetchJSearchAPI = async (position = "Software Developer") => {
  try {
    const encodedPosition = encodeURIComponent(position);
    const url = `https://jsearch.p.rapidapi.com/search?query=${encodedPosition}%20in%20USA&page=1&num_pages=20&remote_jobs_only=false&employment_types=FULLTIME%2C%20PARTTIME%2C%20CONTRACTOR`;
    const options = {
      method: "GET",
      headers: {
        "X-RapidAPI-Key": process.env.API_KEY,
        "X-RapidAPI-Host": "jsearch.p.rapidapi.com",
      },
    };
    const response = await fetch(url, options);
    if (!response.ok) {
      throw new Error(
        `Failed to fetch data: ${response.status} ${response.statusText}`
      );
    }
    const result = await response.json();
    return result.data; // Extracting the job data key array from the response
  } catch (error) {
    console.error(error);
  }
};

//function to convert the employment type to a more readable format
const getEmploymentTypeDescription = (employmentType) => {
  switch (employmentType) {
    case "FULLTIME":
      return "Full-Time";
    case "PARTTIME":
      return "Part-Time";
    case "INTERN":
      return "Internship";
    case "CONTRACTOR":
      return "Contract";
    default:
      return employmentType; // Fallback to the original value if no match is found
  }
};

const insertJobsIntoDatabase = async (jobData) => {
  try {
    // Connect to the database
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
    });

    // Insert job data into the database
    for (const job of jobData) {
      let experienceLevel;
      if (job.job_required_experience.no_experience_required) {
        experienceLevel = "No experience required";
      } else {
        experienceLevel = "Experience required";
      }

      // Convert benefits array to JSON string or set to null
      const benefits = job.job_benefits
        ? JSON.stringify(job.job_benefits)
        : null; 

      //apply function to convert employment type to the property
      const employmentTypeDescription = getEmploymentTypeDescription(
        job.job_employment_type
      );

      await connection.execute(
        "INSERT INTO job (title, company, city, state, is_remote, employment_type, experience_level, job_description, salary_low, salary_high, benefits, website, industry) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
          job.job_title, // title
          job.employer_name, //company
          job.job_city, //city
          job.job_state, //state
          job.job_is_remote ? 1 : 0, //is_remote
          employmentTypeDescription, //employment type
          experienceLevel, //experience_level
          job.job_description, //job_description
          job.job_min_salary || null,
          job.job_max_salary || null,
          benefits,
          job.employer_website || "Not specified",
          job.employer_company_type || "Not specified",
        ]
      );
    }

    // Close the database connection
    await connection.end();
  } catch (error) {
    console.error("Error inserting data into database:", error);
  }
};

const fetchAndSaveJobs = async () => {
  try {
    // Fetch job data from the API
    const jobData = await fetchJSearchAPI();

    // Insert job data into the database
    await insertJobsIntoDatabase(jobData);
  } catch (error) {
    console.error("Error fetching and saving jobs:", error);
  }
};

module.exports = {
  fetchAndSaveJobs,
};
