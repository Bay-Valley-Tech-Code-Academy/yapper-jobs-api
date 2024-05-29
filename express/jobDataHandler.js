const fetch = require("node-fetch");
const mysql = require("mysql2/promise");

const fetchJSearchAPI = async (position = "Software Developer") => {
  try {
    const encodedPosition = encodeURIComponent(position);
    const url = `https://jsearch.p.rapidapi.com/search?query=${encodedPosition}%20in%20USA&page=1&num_pages=20&remote_jobs_only=false&employment_types=FULLTIME%2C%20PARTTIME%2C%20CONTRACTOR`;
    const options = {
      method: "GET",
      headers: {
        "X-RapidAPI-Key": "3d7ce1d4fbmsh9dca1a5f72dab04p1be7eajsn596878a4599b",
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
    return result.data; // Extracting the job data array from the response
  } catch (error) {
    console.error(error);
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
      await connection.execute(
        "INSERT INTO job (title, company, employment_type, location, experience_level, job_description) VALUES (?, ?, ?, ?, ?, ?)",
        [
          job.job_title,
          job.employer_name,
          job.job_employment_type,
          job.job_country,
          experienceLevel,
        //   job.job_min_salary || "Not specified",
        //   job.job_max_salary || "Not specified",
          job.job_description,
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
