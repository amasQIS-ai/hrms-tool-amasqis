import { format } from "date-fns";
import { getsuperadminCollections } from "../../config/db.js";
import { ObjectId } from "mongodb";
import { clerkClient } from "@clerk/clerk-sdk-node";
import sendCredentialsEmail from "../../utils/emailer.js";
import generateRandomPassword from "../../utils/generatePassword.js";

const fetchPackages = async () => {
  try {
    const { packagesCollection } = getsuperadminCollections();

    const rawPackages = await packagesCollection
      .find({ status: "Active" })
      .toArray();

    const data = rawPackages.map((pkg) => ({
      id: pkg._id?.toString(),
      plan_name: pkg.planName || "",
      plan_type: pkg.planType || "",
      currency: pkg.planCurrency || "",
    }));

    const show = data.map((item) => ({
      label: item.plan_name,
      value: item.id,
    }));

    return {
      done: true,
      data,
      show,
    };
  } catch (error) {
    console.error("Failed to fetch packages:", error);
    return {
      done: false,
      error: error,
    };
  }
};

// 1. Send credentials via email

// 3. Main function
const addCompany = async (data, user) => {
  try {
    const { companiesCollection } = getsuperadminCollections();

    // Step 1: Prepare initial company document
    const newCompany = {
      ...data,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdby: user,
    };

    // Step 2: Insert company in DB
    const result = await companiesCollection.insertOne(newCompany);
    const companyId = result.insertedId.toString();

    // Step 3: Generate a random temporary password
    const tempPassword = generateRandomPassword();

    // Step 4: Create Clerk user
    const createdUser = await clerkClient.users.createUser({
      emailAddress: [data.email],
      password: tempPassword,
      publicMetadata: {
        role: "admin",
        company: companyId,
        subdomain: data.domain,
      },
    });

    const clerkUserId = createdUser.id;

    // Step 5: Update the company document with clerkUserId
    await companiesCollection.updateOne(
      { _id: result.insertedId },
      {
        $set: {
          clerkUserId,
          updatedAt: new Date(),
        },
      }
    );

    // Step 6: Send credentials email
    await sendCredentialsEmail({
      to: data.email,
      companyName: data.name,
      password: tempPassword,
      loginLink: "https://devmanagertc.amasqis.ai/login", // Login URL for every company should change
    });

    return {
      done: true,
      message: "Company and user created. Credentials emailed.",
      companyId,
      clerkUserId,
    };
  } catch (error) {
    console.error("Error creating company/org/user:", error);
    return {
      done: false,
      error: error,
    };
  }
};

const fetchCompanylist = async ({ type, startDate, endDate }) => {
  try {
    const { companiesCollection } = getsuperadminCollections();
    const now = new Date();

    const dateFilter = {};

    switch (type) {
      case "today":
        dateFilter.createdAt = {
          $gte: startOfToday(),
        };
        break;
      case "yesterday":
        dateFilter.createdAt = {
          $gte: subDays(startOfToday(), 1),
          $lt: startOfToday(),
        };
        break;
      case "last7days":
        dateFilter.createdAt = {
          $gte: subDays(now, 7),
        };
        break;
      case "last30days":
        dateFilter.createdAt = {
          $gte: subDays(now, 30),
        };
        break;
      case "thismonth":
        dateFilter.createdAt = {
          $gte: startOfMonth(now),
        };
        break;
      case "lastmonth":
        dateFilter.createdAt = {
          $gte: startOfMonth(subMonths(now, 1)),
          $lt: startOfMonth(now),
        };
        break;
      case "custom":
        if (!startDate || !endDate)
          throw new Error("Missing custom date range");
        dateFilter.createdAt = {
          $gte: new Date(startDate),
          $lte: new Date(endDate),
        };
        break;
      default:
        // No filter applied
        break;
    }

    const companies = await companiesCollection
      .find(dateFilter)
      .sort({ createdAt: -1 })
      .toArray();

    const data = companies.map((company, index) => ({
      id: company._id.toString(),
      CompanyName: company.name || "N/A",
      Email: company.email || "N/A",
      AccountURL: company.domain || "N/A",
      Plan: `${company.plan_name || "N/A"} (${company.plan_type || "N/A"})`,
      CreatedDate: company.createdAt
        ? format(new Date(company.createdAt), "d MMM yyyy")
        : "N/A",
      Image: company.logo, // Update this if using real logos
      Status: company.status,
      created_at: company.createdAt,
    }));

    return {
      done: true,
      data,
    };
  } catch (error) {
    return {
      done: false,
      error: error.message,
    };
  }
};

const fetchCompanystats = async () => {
  try {
    const { companiesCollection } = getsuperadminCollections();
    console.log("In db");

    const aggregationPipeline = [
      {
        $facet: {
          // Total plans count
          total_companies: [{ $count: "count" }],

          // Active plans count
          active_companies: [
            { $match: { status: "Active" } },
            { $count: "count" },
          ],

          // Inactive plans count
          inactive_companies: [
            { $match: { status: "Inactive" } },
            { $count: "count" },
          ],
        },
      },
      {
        $project: {
          total_companies: { $arrayElemAt: ["$total_companies.count", 0] },
          active_companies: { $arrayElemAt: ["$active_companies.count", 0] },
          inactive_companies: {
            $arrayElemAt: ["$inactive_companies.count", 0],
          },
        },
      },
    ];

    const [result] = await companiesCollection
      .aggregate(aggregationPipeline)
      .toArray();

    return {
      done: true,
      data: {
        total_companies: "" + (result.total_companies || 0),
        active_companies: "" + (result.active_companies || 0),
        inactive_companies: "" + (result.inactive_companies || 0),
        location: "" + 2,
      },
    };
  } catch (error) {
    console.error("Error fetching plan details:", error);
    return { done: false, message: "Error fetching plan details" };
  }
};

const deleteCompany = async (ids) => {
  try {
    const { companiesCollection } = getsuperadminCollections();

    // Convert string ids to ObjectId if necessary
    const objectIds = ids.map((id) =>
      typeof id === "string" ? new ObjectId(id) : id
    );

    // Delete all records where _id is in the provided ids array
    const result = await companiesCollection.deleteMany({
      _id: { $in: objectIds },
    });

    return {
      done: true,
      message: `${result.deletedCount} companies deleted successfully.`,
      data: null,
    };
  } catch (error) {
    console.error("Error deleting plans:", error);
    return {
      done: false,
      message: error.message,
      data: null,
    };
  }
};

const fetchcompany = async (companyid) => {
  try {
    const { companiesCollection, packagesCollection } =
      getsuperadminCollections();

    // Fetch company details
    const details = await companiesCollection.findOne({
      _id: new ObjectId(companyid),
    });
    if (!details) throw new Error("Company not found");

    // Fetch package details
    const packagedetails = await packagesCollection.findOne({
      _id: new ObjectId(details.plan_id),
    });
    if (!packagedetails) throw new Error("Package not found");

    // Calculate register and expiry dates
    const registerDate = new Date(details.createdAt); // assuming 'createdAt' exists
    let expireDate;

    if (details.plan_type === "Yearly") {
      expireDate = new Date(registerDate);
      expireDate.setFullYear(expireDate.getFullYear() + 1);
    } else if (details.plan_type === "Monthly") {
      expireDate = new Date(registerDate);
      expireDate.setMonth(expireDate.getMonth() + 1);
    } else {
      expireDate = null;
    }

    // Format dates as "DD-MM-YYYY"
    const formatDate = (date) => date.toLocaleDateString("en-GB");

    return {
      done: true,
      data: {
        name: details.name,
        email: details.email,
        status: details.status,
        domain: details.domain,
        phone: details.phone,
        website: details.website,
        address: details.address,
        currency: details.currency,
        plan_name: details.plan_name,
        plan_type: details.plan_type,
        price: packagedetails.price,
        registerdate: formatDate(registerDate),
        expiredate: formatDate(expireDate),
        logo: details.logo,
      },
    };
  } catch (error) {
    console.error("Error fetching company:", error);
    return {
      done: false,
      message: error.message || "Something went wrong",
    };
  }
};

const fetcheditcompanyview = async (companyid) => {
  try {
    const { companiesCollection } = getsuperadminCollections();

    // Fetch company details
    const details = await companiesCollection.findOne({
      _id: new ObjectId(companyid),
    });
    if (!details) throw new Error("Company not found");

    return {
      done: true,
      data: {
        id: companyid,
        name: details.name,
        email: details.email,
        status: details.status,
        domain: details.domain,
        phone: details.phone,
        website: details.website,
        address: details.address,
        plan_id: details.plan_id,
        plan_name: details.plan_name,
        plan_type: details.plan_type,
        logo: details.logo,
      },
    };
  } catch (error) {
    console.error("Error fetching company:", error);
    return {
      done: false,
      message: error.message || "Something went wrong",
    };
  }
};

const updateCompany = async (form) => {
  try {
    const { companiesCollection } = getsuperadminCollections();
    // 1. First find the existing document
    const existingcompany = await companiesCollection.findOne({
      _id: new ObjectId(form.id),
    });

    console.log("DIB");

    if (!existingcompany) {
      throw new Error("Plan not found");
    }
    console.log("Status now ->", form.status);

    // 2. Prepare the update data - merge new form with preserved fields
    const updateData = {
      name: form.name,
      email: form.email,
      domain: form.domain,
      phone: form.phone,
      website: form.website,
      address: form.address,
      status: form.status,
      currency: form.currency,
      plan_name: form.plan_name,
      plan_type: form.plan_type,
      plan_id: form.plan_id,
      created_by: existingcompany.created_by,
      updatedAt: new Date().toISOString(),
      logo: form.logo,
      // Make sure to convert planModules array to the format your schema expects
    };

    // 3. Perform the update
    const result = await companiesCollection.updateOne(
      { _id: new ObjectId(form.id) },
      { $set: updateData }
    );

    // if (result.modifiedCount === 0) {
    //   throw new Error("No changes made or plan not found");
    // }

    return {
      done: true,
      message: "Plan updated successfully",
      // data: { ...updateData, _id: form._id },
    };
  } catch (error) {
    console.error("Error updating plan:", error);
    return {
      done: false,
      error: error,
      data: null,
    };
  }
};

export {
  fetchPackages,
  addCompany,
  fetchCompanylist,
  fetchCompanystats,
  deleteCompany,
  fetchcompany,
  fetcheditcompanyview,
  updateCompany,
};
