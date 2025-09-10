import React, { useEffect, useRef, useState } from "react";

import { Link } from "react-router-dom";
import { all_routes } from "../../router/all_routes";
import PredefinedDateRanges from "../../../core/common/datePicker";
import { companies_details } from "../../../core/data/json/companiesdetails";
import ImageWithBasePath from "../../../core/common/imageWithBasePath";
import Table from "../../../core/common/dataTable/index";
import CommonSelect from "../../../core/common/commonSelect";
import { DatePicker } from "antd";
import ReactApexChart from "react-apexcharts";
import CollapseHeader from "../../../core/common/collapse-header/collapse-header";
import { useSocket } from "../../../SocketContext";
import { Socket } from "socket.io-client";
import "react-toastify/dist/ReactToastify.css";
import Skeleton, { SkeletonTheme } from "react-loading-skeleton";
import "react-loading-skeleton/dist/skeleton.css";
import { ToastContainer, toast } from "react-toastify";
import moment from "moment";
type PasswordField = "password" | "confirmPassword";

const Companies = () => {
  // Socket
  const socket = useSocket() as Socket | null;
  const [resetKey, setResetKey] = useState(0);
  const [deleteplan, setdeleteplan] = useState<any>([]);
  const [deleteLoader, setdeleteLoader] = useState(false);
  const [confirmText, setConfirmText] = useState("");
  const data = companies_details;
  const [viewcompanyloader, setviewcompanyloader] = useState(false);
  const [editcompanyloader, seteditcompanyloader] = useState(false);
  const [isLoadingediting, setisLoadingediting] = useState(false);

  type companydetail = {
    name: string;
    email: string;
    status: string;
    domain: string;
    phone: string;
    website: string;
    currency: string;
    address: string;
    plan_type: string;
    plan_name: string;
    expiredate: string;
    price: string;
    registerdate: string;
    logo: string;
  };

  const [companydetail, setcompanydetail] = useState<companydetail>({
    name: "Bytecamp Technologies",
    email: "contact@bytecamp.in",
    status: "Active",
    domain: "bytecamp.in",
    phone: "+91 9876543210",
    website: "https://bytecamp.in",
    currency: "INR",
    address: "Chennai, Tamil Nadu, India",
    plan_name: "Enterprise",
    plan_type: "Yearly",
    price: "₹19,999",
    registerdate: "2025-01-01",
    expiredate: "2025-12-31",
    logo: "",
  });

  const viewCompanyDetails = (id: string) => {
    setviewcompanyloader(true);
    socket?.emit("superadmin/companies/view-company", id);
  };

  const editcompany = (id: string) => {
    seteditcompanyloader(true);
    socket?.emit("superadmin/companies/view-company", id, true);
  };

  const columns = [
    {
      title: "Company Name",
      dataIndex: "CompanyName",
      render: (text: String, record: any) => (
        <div className="d-flex align-items-center file-name-icon">
          <Link to="#" className="avatar avatar-md border rounded-circle">
            <ImageWithBasePath
              isLink={true}
              src={record.Image}
              className="img-fluid"
              alt="img"
            />
          </Link>
          <div className="ms-2">
            <h6 className="fw-medium">
              <Link to="#">{record.CompanyName}</Link>
            </h6>
          </div>
        </div>
      ),
      sorter: (a: any, b: any) => a.CompanyName.length - b.CompanyName.length,
    },
    {
      title: "Email",
      dataIndex: "Email",
      sorter: (a: any, b: any) => a.Email.length - b.Email.length,
    },
    {
      title: "Account URL",
      dataIndex: "AccountURL",
      sorter: (a: any, b: any) => a.AccountURL.length - b.AccountURL.length,
    },
    {
      title: "Plan",
      dataIndex: "Plan",
      render: (text: String, record: any) => (
        <div className="d-flex align-items-center justify-content-between">
          <p className="mb-0 me-2">{record.Plan}</p>
          <Link
            to="#"
            data-bs-toggle="modal"
            className="badge badge-purple badge-xs"
            data-bs-target="#upgrade_info"
          >
            Upgrade
          </Link>
        </div>
      ),
      sorter: (a: any, b: any) => a.Plan.length - b.Plan.length,
    },
    {
      title: "Created Date",
      dataIndex: "CreatedDate",
      sorter: (a: any, b: any) => a.CreatedDate.length - b.CreatedDate.length,
    },
    {
      title: "Status",
      dataIndex: "Status",
      render: (text: string, record: any) => (
        <span
          className={`badge ${
            text === "Active" ? "badge-success" : "badge-danger"
          } d-inline-flex align-items-center badge-xs`}
        >
          <i className="ti ti-point-filled me-1" />
          {text}
        </span>
      ),
      sorter: (a: any, b: any) => a.Status.length - b.Status.length,
    },
    {
      title: "",
      dataIndex: "actions",
      render: (_: any, record: any) => (
        <div className="action-icon d-inline-flex">
          <Link
            to="#"
            className="me-2"
            data-bs-toggle="modal"
            data-bs-target="#company_detail"
            onClick={() => {
              viewCompanyDetails(record.id);
            }}
          >
            <i className="ti ti-eye" />
          </Link>
          <Link
            to="#"
            className="me-2"
            data-bs-toggle="modal"
            data-bs-target="#edit_company"
            onClick={() => {
              editcompany(record.id);
            }}
          >
            <i className="ti ti-edit" />
          </Link>
          <Link
            to="#"
            data-bs-toggle="modal"
            data-bs-target="#delete_modal"
            onClick={() => {
              setdeleteplan([record.id]);
            }}
          >
            <i className="ti ti-trash" />
          </Link>
        </div>
      ),
    },
  ];
  const [passwordVisibility, setPasswordVisibility] = useState({
    password: false,
    confirmPassword: false,
  });

  const [company_details, setcompany_details] = useState<any>({
    total_companies: null,
    active_companies: null,
    inactive_companies: null,
    location: null,
  });

  const togglePasswordVisibility = (field: PasswordField) => {
    setPasswordVisibility((prevState) => ({
      ...prevState,
      [field]: !prevState[field],
    }));
  };

  const [Package, setPackage] = useState<
    { id: string; plan_name: string; plan_type: string; currency: string }[]
  >([]);
  // This is for dynamically Updation of package

  const [planName, setPlanName] = useState<{ value: string; label: string }[]>(
    []
  );

  const planType = [
    { value: "Monthly", label: "Monthly" },
    { value: "Yearly", label: "Yearly" },
  ];
  const currency = [
    { value: "USD", label: "USD" },
    { value: "Euro", label: "Euro" },
  ];
  const language = [
    { value: "English", label: "English" },
    { value: "Arabic", label: "Arabic" },
  ];
  const statusChoose = [
    { value: "Active", label: "Active" },
    { value: "Inactive", label: "Inactive" },
  ];

  // Use State Data
  const [Data, setData] = useState<any[]>([]);
  const [logo, setLogo] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [imageupload, setimageupload] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [inputKey, setInputKey] = useState(Date.now());
  const [tableLoading, settableLoading] = useState(true);
  const defaultAllTimeStart = moment.utc("1970-01-01T00:00:00Z").toISOString();
  const defaultAllTimeEnd = moment.utc().toISOString();
  const [tempfiltereddata, settempfiltereddata] = useState<any>(undefined);
  const [filters, setFilters] = useState({
    status: "", // 'Active' or 'Inactive'
    dateRange: {
      start: defaultAllTimeStart,
      end: defaultAllTimeEnd,
    },
  });

  // Filter option

  useEffect(() => {
    if (filters && Data) {
      console.log("Filters updated:", filters);
      console.log("Data updated:", Data);
      let result = [...Data]; // Always start from the original Data

      if (filters.status) {
        console.log(filters.status);
        console.log(result);
        result = result.filter((data) => data.Status === filters.status);
      }

      // Date Filtering
      if (filters.dateRange?.start || filters.dateRange?.end) {
        result = result.filter((data) => {
          const compDate = new Date(data.created_at);
          let start = filters.dateRange.start
            ? new Date(filters.dateRange.start)
            : null;
          let end = filters.dateRange.end
            ? new Date(filters.dateRange.end)
            : null;

          if (start) start.setHours(0, 0, 0, 0);
          if (end) end.setHours(23, 59, 59, 999);

          return (!start || compDate >= start) && (!end || compDate <= end);
        });
      }
      console.log("Rsukt deb", result);
      settempfiltereddata(result); // Store filtered data for reuse
    }
  }, [filters, Data]); // Removed tempfiltereddata from dependencies

  // Form Data

  const [formData, setFormData] = useState({
    name: "",
    email: "",
    domain: "",
    phone: "",
    website: "",
    address: "",
    status: "Active",
    plan_name: "",
    plan_type: "",
    plan_id: "",
    currency: "",
  });

  // Helper functions

  useEffect(() => {
    const selectedPackage = Package.find((pkg) => pkg.id === formData.plan_id);

    if (selectedPackage) {
      setFormData((prev) => ({
        ...prev,
        plan_name: selectedPackage.plan_name,
        currency: selectedPackage.currency,
        plan_type: selectedPackage.plan_type,
      }));
    }
    console.log(formData);
  }, [formData.plan_id]);

  const uploadImage = async (file: File): Promise<string | null> => {
    setLogo(null);
    const formData = new FormData();
    formData.append("file", file);
    formData.append("upload_preset", "amasqis"); // Replace with your Cloudinary Upload Preset

    const res = await fetch(
      "https://api.cloudinary.com/v1_1/dwc3b5zfe/image/upload",
      {
        method: "POST",
        body: formData,
      }
    );

    const data = await res.json();
    console.log(data);
    return data.secure_url; // This is the image URL to store in DB
  };

  const handleImageUpload = async (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = event.target.files?.[0];

    if (!file) {
      return; // No file selected
    }

    const maxSize = 4 * 1024 * 1024; // 3MB in bytes
    if (file.size > maxSize) {
      toast.error("File size must be less than 4MB.", {
        position: "top-right",
        autoClose: 3000,
        hideProgressBar: true,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
      });
      event.target.value = ""; // Clear the file input
      return;
    }

    if (
      file &&
      ["image/jpeg", "image/png", "image/jpg", "image/ico"].includes(file.type)
    ) {
      setimageupload(true);
      const uploadedUrl = await uploadImage(file);
      setLogo(uploadedUrl);
      console.log(uploadedUrl);
      setimageupload(false);
    } else {
      toast.error(`Please Upload Image file only.`, {
        position: "top-right",
        autoClose: 3000,
        hideProgressBar: true,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
      });
      event.target.value = "";
    }
  };

  const RemoveLogo = () => {
    setLogo(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  // Input Change

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target;
    const processedValue = type === "number" ? parseFloat(value) : value;

    setFormData((prevState) => ({
      ...prevState,
      [name]: type === "checkbox" ? checked : processedValue,
    }));
  };

  // Common Select Change

  type SelectOption = {
    label: string;
    value: string | number;
  };

  const handleSelectChange = (
    name: string,
    selectedOption: SelectOption | null
  ) => {
    if (!selectedOption) return;
    setFormData((prevState) => ({
      ...prevState,
      [name]: selectedOption.value,
    }));
  };

  // Socket Requests

  // Fetch All Package Details

  useEffect(() => {
    if (!socket) return;
    socket.emit("superadmin/companies/fetch-packages");
    socket.emit("superadmin/companies/fetch-companylist", "All");
    socket.emit("superadmin/companies/fetch-companystats");
  }, [socket]);

  useEffect(() => {
    if (!socket) return;

    type PackageItem = {
      id: string;
      plan_name: string;
      plan_type: string;
      currency: string;
    };

    type PackageSelectOption = {
      label: string;
      value: string;
    };

    type FetchPackagesResponse = {
      done: boolean;
      data?: PackageItem[];
      show?: PackageSelectOption[];
      error?: any;
    };

    const fetchpackageHandler = (response: FetchPackagesResponse) => {
      if (response.done && response.data) {
        console.log(response);
        setPackage(response.data);
        setPlanName(response.show ?? []);
      } else {
        toast.error("Failed to fetch packages", {
          position: "top-right",
          autoClose: 3000,
          hideProgressBar: true,
          closeOnClick: true,
          pauseOnHover: true,
          draggable: true,
        });

        console.error("Package fetch error:", response.error);
      }
    };

    const addCompanyHandler = (response: FetchPackagesResponse) => {
      if (response.done) {
        setIsLoading(false);
        reset_form();
        toast.success("Company Added Successfully");
      } else {
        setIsLoading(false);
        toast.error("Failed to add company");
        console.log(response.error);
      }
    };

    const companylistResponse = (response: FetchPackagesResponse) => {
      if (response.done && Array.isArray(response.data)) {
        settableLoading(false);
        setData(response.data);
      } else {
        console.error("Invalid data format:", response);
      }
    };

    const companyStatsHandler = (response: FetchPackagesResponse) => {
      if (response.done) {
        setcompany_details(response.data);
      } else {
        console.error("Invalid data format, stats company:", response);
      }
    };

    const deleteCompanyHandler = (response: FetchPackagesResponse) => {
      setdeleteLoader(false);
      if (response.done) {
        toast.success("Deletion Successful");
      } else {
        toast.error("Deletion Failed");
        console.log(response.error);
      }
    };

    const viewcompanyHandler = (response: any) => {
      if (response.done) {
        setcompanydetail(response.data);
        setviewcompanyloader(false);
      } else {
        toast.error("Cannot fetch the details");
        setviewcompanyloader(false);
      }
    };

    const editviewcompanyHandler = (response: any) => {
      if (response.done) {
        setFormData(response.data);
        setLogo(response.data.logo);
        seteditcompanyloader(false);
      } else {
        toast.error("Error fetching the details");
        console.log(response.error);
      }
    };

    const handleEditCompany = (response: any) => {
      if (response.done) {
        reset_form();
        setisLoadingediting(false);
        toast.success("Company Updated Successfully");
      } else {
        toast.error("Company Updated failed");
        console.log(response.error);
      }
    };

    socket.on(
      "superadmin/companies/fetch-packages-response",
      fetchpackageHandler
    );

    socket.on("superadmin/companies/add-company-response", addCompanyHandler);

    // Page inital loading Response
    socket.on(
      "superadmin/companies/fetch-companylist-response",
      companylistResponse
    );

    socket.on(
      "superadmin/companies/fetch-companystats-response",
      companyStatsHandler
    );

    socket.on(
      "superadmin/companies/delete-company-response",
      deleteCompanyHandler
    );

    // View spefic company
    socket.on("superadmin/companies/view-company-response", viewcompanyHandler);

    socket.on(
      "superadmin/companies/editview-company-response",
      editviewcompanyHandler
    );

    socket.on("superadmin/companies/edit-company-response", handleEditCompany);

    return () => {
      socket.off(
        "superadmin/companies/fetch-packages-response",
        fetchpackageHandler
      );
      socket.off(
        "superadmin/companies/add-company-response",
        addCompanyHandler
      );
      socket.off(
        "superadmin/companies/fetch-companylist-response",
        companylistResponse
      );

      socket.off(
        "superadmin/companies/fetch-companystats-response",
        companyStatsHandler
      );
      socket.off(
        "superadmin/companies/delete-company-response",
        deleteCompanyHandler
      );
      socket.off(
        "superadmin/companies/view-company-response",
        viewcompanyHandler
      );

      socket.off(
        "superadmin/companies/editview-company-response",
        editviewcompanyHandler
      );

      socket.off(
        "superadmin/companies/edit-company-response",
        handleEditCompany
      );
    };
  }, [socket]);

  // Host Fetch Dynamic

  const [hostSuffix, setHostSuffix] = useState("");
  useEffect(() => {
    const hostname = window.location.hostname;
    const parts = hostname.split(".");
    if (parts.length > 2) {
      // join last 2 parts as suffix
      setHostSuffix(`.${parts.slice(-2).join(".")}`);
    } else {
      setHostSuffix(`.${hostname}`); // fallback if hostname is simple
    }
  }, []);

  // Handle add Company Form Submit

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    // Validate required fields
    const requiredFields = [
      { field: "plan_name", label: "Plan Name" },
      // { field: "plan_type", label: "Plan Type" },
      // { field: "currency", label: "Currency" },
      // { field: "plan_id", label: "Plan Name" },
    ];

    let hasError = false;
    const formRecord = formData as Record<string, any>;
    console.log("form record", formRecord);
    requiredFields.forEach(({ field, label }) => {
      const value = formRecord[field];
      if (value === null || value === undefined || value === "") {
        toast.error(`Please select a value for ${label}.`, {
          position: "top-right",
          autoClose: 3000,
          hideProgressBar: true,
          closeOnClick: true,
          pauseOnHover: true,
          draggable: true,
        });
        hasError = true;
      }
    });

    // Stop submission if there are errors
    if (hasError) {
      setIsLoading(false); // Disable loading state
      console.log("Error");
      return;
    }

    setIsLoading(true); // Enable loading state

    // Prepare the data to be submitted

    // Emit the data via socket

    const formDataWithLogo = {
      ...formData,
      logo: logo,
    };

    console.log("[DEV] - ", formDataWithLogo);

    socket?.emit("superadmin/companies/add-company", formDataWithLogo);
  };
  const EdithandleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    // Validate required fields
    const requiredFields = [{ field: "plan_name", label: "Plan Name" }];

    let hasError = false;
    const formRecord = formData as Record<string, any>;
    console.log("form record", formRecord);
    requiredFields.forEach(({ field, label }) => {
      const value = formRecord[field];
      if (value === null || value === undefined || value === "") {
        toast.error(`Please select a value for ${label}.`, {
          position: "top-right",
          autoClose: 3000,
          hideProgressBar: true,
          closeOnClick: true,
          pauseOnHover: true,
          draggable: true,
        });
        hasError = true;
      }
    });

    if (logo == null || logo == undefined || logo.trim() == "") {
      hasError = true;
      toast.error("Please upload a Logo.");
    }

    // Stop submission if there are errors
    if (hasError) {
      setisLoadingediting(false); // Disable loading state
      console.log("Error");
      return;
    }

    setisLoadingediting(true); // Enable loading state

    // Prepare the data to be submitted

    // Emit the data via socket

    const formDataWithLogo = {
      ...formData,
      logo: logo,
    };

    console.log("[DEV] - ", formDataWithLogo);

    socket?.emit("superadmin/companies/edit-company", formDataWithLogo);
  };

  // Reset form

  const reset_form = () => {
    setFormData({
      name: "",
      email: "",
      domain: "",
      phone: "",
      website: "",
      address: "",
      status: "Active",
      plan_name: "",
      plan_type: "",
      plan_id: "",
      currency: "",
    });
    RemoveLogo();
    const elements = document.querySelectorAll('[id="close-add-company"]');

    if (elements.length > 0) {
      elements.forEach((el) => (el as HTMLElement).click());
    }

    setResetKey((prevKey) => prevKey + 1);
  };

  // Delete Companies

  const DeletePlan = () => {
    if (deleteplan.length > 0) {
      setdeleteLoader(true);
      socket?.emit("superadmin/companies/delete-company", deleteplan);
      setdeleteplan([]);
    }
  };

  const getModalContainer = () => {
    const modalElement = document.getElementById("modal-datepicker");
    return modalElement ? modalElement : document.body; // Fallback to document.body if modalElement is null
  };

  const [totalChart] = React.useState<any>({
    series: [
      {
        name: "Messages",
        data: [25, 66, 41, 12, 36, 9, 21],
      },
    ],
    fill: {
      type: "gradient",
      gradient: {
        opacityFrom: 0, // Start with 0 opacity (transparent)
        opacityTo: 0, // End with 0 opacity (transparent)
      },
    },
    chart: {
      foreColor: "#fff",
      type: "area",
      width: 50,
      toolbar: {
        show: !1,
      },
      zoom: {
        enabled: !1,
      },
      dropShadow: {
        enabled: 0,
        top: 3,
        left: 14,
        blur: 4,
        opacity: 0.12,
        color: "#fff",
      },
      sparkline: {
        enabled: !0,
      },
    },
    markers: {
      size: 0,
      colors: ["#F26522"],
      strokeColors: "#fff",
      strokeWidth: 2,
      hover: {
        size: 7,
      },
    },
    plotOptions: {
      bar: {
        horizontal: !1,
        columnWidth: "35%",
        endingShape: "rounded",
      },
    },
    dataLabels: {
      enabled: !1,
    },
    stroke: {
      show: !0,
      width: 2.5,
      curve: "smooth",
    },
    colors: ["#F26522"],
    xaxis: {
      categories: [
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
      ],
    },
    tooltip: {
      theme: "dark",
      fixed: {
        enabled: !1,
      },
      x: {
        show: !1,
      },
      y: {
        title: {
          formatter: function (e: any) {
            return "";
          },
        },
      },
      marker: {
        show: !1,
      },
    },
  });
  const [activeChart] = React.useState<any>({
    series: [
      {
        name: "Active Company",
        data: [25, 40, 35, 20, 36, 9, 21],
      },
    ],
    fill: {
      type: "gradient",
      gradient: {
        opacityFrom: 0, // Start with 0 opacity (transparent)
        opacityTo: 0, // End with 0 opacity (transparent)
      },
    },
    chart: {
      foreColor: "#fff",
      type: "area",
      width: 50,
      toolbar: {
        show: !1,
      },
      zoom: {
        enabled: !1,
      },
      dropShadow: {
        enabled: 0,
        top: 3,
        left: 14,
        blur: 4,
        opacity: 0.12,
        color: "#fff",
      },
      sparkline: {
        enabled: !0,
      },
    },
    markers: {
      size: 0,
      colors: ["#F26522"],
      strokeColors: "#fff",
      strokeWidth: 2,
      hover: {
        size: 7,
      },
    },
    plotOptions: {
      bar: {
        horizontal: !1,
        columnWidth: "35%",
        endingShape: "rounded",
      },
    },
    dataLabels: {
      enabled: !1,
    },
    stroke: {
      show: !0,
      width: 2.5,
      curve: "smooth",
    },
    colors: ["#F26522"],
    xaxis: {
      categories: [
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
      ],
    },
    tooltip: {
      theme: "dark",
      fixed: {
        enabled: !1,
      },
      x: {
        show: !1,
      },
      y: {
        title: {
          formatter: function (e: any) {
            return "";
          },
        },
      },
      marker: {
        show: !1,
      },
    },
  });
  const [inactiveChart] = React.useState<any>({
    series: [
      {
        name: "Inactive Company",
        data: [25, 10, 35, 5, 25, 28, 21],
      },
    ],
    fill: {
      type: "gradient",
      gradient: {
        opacityFrom: 0, // Start with 0 opacity (transparent)
        opacityTo: 0, // End with 0 opacity (transparent)
      },
    },
    chart: {
      foreColor: "#fff",
      type: "area",
      width: 50,
      toolbar: {
        show: !1,
      },
      zoom: {
        enabled: !1,
      },
      dropShadow: {
        enabled: 0,
        top: 3,
        left: 14,
        blur: 4,
        opacity: 0.12,
        color: "#fff",
      },
      sparkline: {
        enabled: !0,
      },
    },
    markers: {
      size: 0,
      colors: ["#F26522"],
      strokeColors: "#fff",
      strokeWidth: 2,
      hover: {
        size: 7,
      },
    },
    plotOptions: {
      bar: {
        horizontal: !1,
        columnWidth: "35%",
        endingShape: "rounded",
      },
    },
    dataLabels: {
      enabled: !1,
    },
    stroke: {
      show: !0,
      width: 2.5,
      curve: "smooth",
    },
    colors: ["#F26522"],
    xaxis: {
      categories: [
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
      ],
    },
    tooltip: {
      theme: "dark",
      fixed: {
        enabled: !1,
      },
      x: {
        show: !1,
      },
      y: {
        title: {
          formatter: function (e: any) {
            return "";
          },
        },
      },
      marker: {
        show: !1,
      },
    },
  });
  const [locationChart] = React.useState<any>({
    series: [
      {
        name: "Inactive Company",
        data: [30, 40, 15, 23, 20, 23, 25],
      },
    ],
    fill: {
      type: "gradient",
      gradient: {
        opacityFrom: 0, // Start with 0 opacity (transparent)
        opacityTo: 0, // End with 0 opacity (transparent)
      },
    },
    chart: {
      foreColor: "#fff",
      type: "area",
      width: 50,
      toolbar: {
        show: !1,
      },
      zoom: {
        enabled: !1,
      },
      dropShadow: {
        enabled: 0,
        top: 3,
        left: 14,
        blur: 4,
        opacity: 0.12,
        color: "#fff",
      },
      sparkline: {
        enabled: !0,
      },
    },
    markers: {
      size: 0,
      colors: ["#F26522"],
      strokeColors: "#fff",
      strokeWidth: 2,
      hover: {
        size: 7,
      },
    },
    plotOptions: {
      bar: {
        horizontal: !1,
        columnWidth: "35%",
        endingShape: "rounded",
      },
    },
    dataLabels: {
      enabled: !1,
    },
    stroke: {
      show: !0,
      width: 2.5,
      curve: "smooth",
    },
    colors: ["#F26522"],
    xaxis: {
      categories: [
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
      ],
    },
    tooltip: {
      theme: "dark",
      fixed: {
        enabled: !1,
      },
      x: {
        show: !1,
      },
      y: {
        title: {
          formatter: function (e: any) {
            return "";
          },
        },
      },
      marker: {
        show: !1,
      },
    },
  });

  return (
    <>
      <SkeletonTheme>
        {/* Page Wrapper */}
        <div className="page-wrapper">
          <div className="content">
            {/* Breadcrumb */}
            <div className="d-md-flex d-block align-items-center justify-content-between page-breadcrumb mb-3">
              <div className="my-auto mb-2">
                <h2 className="mb-1">Companies</h2>
                <nav>
                  <ol className="breadcrumb mb-0">
                    <li className="breadcrumb-item">
                      <Link to={all_routes.adminDashboard}>
                        <i className="ti ti-smart-home" />
                      </Link>
                    </li>
                    <li className="breadcrumb-item">Application</li>
                    <li className="breadcrumb-item active" aria-current="page">
                      Companies List
                    </li>
                  </ol>
                </nav>
              </div>
              <div className="d-flex my-xl-auto right-content align-items-center flex-wrap ">
                <div className="me-2 mb-2">
                  <div className="dropdown">
                    <Link
                      to="#"
                      className="dropdown-toggle btn btn-white d-inline-flex align-items-center"
                      data-bs-toggle="dropdown"
                    >
                      <i className="ti ti-file-export me-1" />
                      Export
                    </Link>
                    <ul className="dropdown-menu  dropdown-menu-end p-3">
                      <li>
                        <Link to="#" className="dropdown-item rounded-1">
                          <i className="ti ti-file-type-pdf me-1" />
                          Export as PDF
                        </Link>
                      </li>
                      <li>
                        <Link to="#" className="dropdown-item rounded-1">
                          <i className="ti ti-file-type-xls me-1" />
                          Export as Excel{" "}
                        </Link>
                      </li>
                    </ul>
                  </div>
                </div>
                <div className="mb-2">
                  <Link
                    to="#"
                    data-bs-toggle="modal"
                    data-bs-target="#add_company"
                    className="btn btn-primary d-flex align-items-center"
                    onClick={reset_form}
                  >
                    <i className="ti ti-circle-plus me-2" />
                    Add Company
                  </Link>
                </div>
                <div className="ms-2 head-icons">
                  <CollapseHeader />
                </div>
              </div>
            </div>
            {/* /Breadcrumb */}
            <div className="row">
              {/* Total Companies */}
              <div className="col-lg-3 col-md-6 d-flex">
                <div className="card flex-fill">
                  <div className="card-body d-flex align-items-center justify-content-between">
                    <div className="d-flex align-items-center overflow-hidden">
                      <span className="avatar avatar-lg bg-primary flex-shrink-0">
                        <i className="ti ti-building fs-16" />
                      </span>
                      <div className="ms-2 overflow-hidden">
                        <p className="fs-12 fw-medium mb-1 text-truncate">
                          Total Companies
                        </p>
                        <h4>
                          {company_details.total_companies || <Skeleton />}
                        </h4>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              {/* /Total Companies */}
              {/* Total Companies */}
              <div className="col-lg-3 col-md-6 d-flex">
                <div className="card flex-fill">
                  <div className="card-body d-flex align-items-center justify-content-between">
                    <div className="d-flex align-items-center overflow-hidden">
                      <span className="avatar avatar-lg bg-success flex-shrink-0">
                        <i className="ti ti-building fs-16" />
                      </span>
                      <div className="ms-2 overflow-hidden">
                        <p className="fs-12 fw-medium mb-1 text-truncate">
                          Active Companies
                        </p>
                        <h4>
                          {company_details.active_companies || <Skeleton />}
                        </h4>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              {/* /Total Companies */}
              {/* Inactive Companies */}
              <div className="col-lg-3 col-md-6 d-flex">
                <div className="card flex-fill">
                  <div className="card-body d-flex align-items-center justify-content-between">
                    <div className="d-flex align-items-center overflow-hidden">
                      <span className="avatar avatar-lg bg-danger flex-shrink-0">
                        <i className="ti ti-building fs-16" />
                      </span>
                      <div className="ms-2 overflow-hidden">
                        <p className="fs-12 fw-medium mb-1 text-truncate">
                          Inactive Companies
                        </p>
                        <h4>
                          {company_details.inactive_companies || <Skeleton />}
                        </h4>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              {/* /Inactive Companies */}
              {/* Company Location */}
              <div className="col-lg-3 col-md-6 d-flex">
                <div className="card flex-fill">
                  <div className="card-body d-flex align-items-center justify-content-between">
                    <div className="d-flex align-items-center overflow-hidden">
                      <span className="avatar avatar-lg bg-skyblue flex-shrink-0">
                        <i className="ti ti-map-pin-check fs-16" />
                      </span>
                      <div className="ms-2 overflow-hidden">
                        <p className="fs-12 fw-medium mb-1 text-truncate">
                          Company Location
                        </p>
                        <h4>{company_details.location || <Skeleton />}</h4>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <div className="modal fade" id="delete_modal">
                <div className="modal-dialog modal-dialog-centered">
                  <div className="modal-content">
                    <div className="modal-body text-center">
                      <span className="avatar avatar-xl bg-transparent-danger text-danger mb-3">
                        <i className="ti ti-trash-x fs-36" />
                      </span>
                      <h4 className="mb-1">Confirm Delete</h4>

                      <p className="mb-3">
                        {deleteplan.length > 1
                          ? `You want to delete all the marked items, this can't be undone once you delete.`
                          : `Please type DELETE to confirm deletion.`}
                      </p>

                      {/* Input for confirmation only if there's something to delete */}
                      {deleteplan.length > 0 && (
                        <input
                          type="text"
                          className="form-control mb-3 text-center"
                          placeholder="Type DELETE to confirm"
                          value={confirmText}
                          onChange={(e) =>
                            setConfirmText(e.target.value.toUpperCase())
                          }
                        />
                      )}

                      <div className="d-flex justify-content-center">
                        <Link
                          to="#"
                          className="btn btn-light me-3"
                          data-bs-dismiss="modal"
                          id="close-delete-plan"
                          onClick={() => {
                            setdeleteplan([]);
                            setConfirmText("");
                          }}
                        >
                          Cancel
                        </Link>

                        {/* Disable Delete button if confirmText !== "DELETE" */}
                        {deleteLoader ? (
                          <Link
                            to="#"
                            data-bs-dismiss="modal"
                            className="btn btn-danger"
                            onClick={DeletePlan}
                          >
                            <span
                              className="spinner-border spinner-border-sm me-2"
                              role="status"
                              aria-hidden="true"
                            />
                            Deleting...
                          </Link>
                        ) : (
                          <Link
                            to="#"
                            data-bs-dismiss={
                              confirmText === "DELETE" ? "modal" : undefined
                            }
                            className={`btn btn-danger ${
                              confirmText !== "DELETE" ? "disabled" : ""
                            }`}
                            onClick={
                              confirmText === "DELETE"
                                ? DeletePlan
                                : (e) => e.preventDefault()
                            }
                          >
                            Yes, Delete
                          </Link>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              {/* /Company Location */}
            </div>
            <div className="card">
              <div className="card-header d-flex align-items-center justify-content-between flex-wrap row-gap-3">
                <h5>Companies List</h5>
                <div className="d-flex my-xl-auto right-content align-items-center flex-wrap row-gap-3">
                  {deleteplan.length > 1 && (
                    <div className="me-3">
                      <button
                        type="button"
                        data-bs-toggle="modal"
                        data-bs-target="#delete_modal"
                        className="btn btn-primary me-2"
                      >
                        Delete Selected
                      </button>
                    </div>
                  )}
                  <div className="me-3">
                    <div className="input-icon-end position-relative">
                      <PredefinedDateRanges
                        value={filters.dateRange}
                        onChange={(range) => {
                          setFilters((prev) => ({
                            ...prev,
                            dateRange: {
                              start: range.start,
                              end: range.end,
                            },
                          }));
                        }}
                      />
                      <span className="input-icon-addon">
                        <i className="ti ti-chevron-down" />
                      </span>
                    </div>
                  </div>
                  {/* <div className="dropdown me-3">
                  <Link
                    to="#"
                    className="dropdown-toggle btn btn-white d-inline-flex align-items-center"
                    data-bs-toggle="dropdown"
                  >
                    Select Plan
                  </Link>
                  <ul className="dropdown-menu  dropdown-menu-end p-3">
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        Advanced
                      </Link>
                    </li>
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        Basic
                      </Link>
                    </li>
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        Enterprise
                      </Link>
                    </li>
                  </ul>
                </div> */}
                  <div className="dropdown me-3">
                    <button
                      className="dropdown-toggle btn btn-white d-inline-flex align-items-center"
                      data-bs-toggle="dropdown"
                      aria-expanded="false"
                    >
                      {filters.status ? filters.status : "Select Status"}
                    </button>
                    <ul className="dropdown-menu dropdown-menu-end p-3">
                      <li>
                        <button
                          className="dropdown-item rounded-1"
                          onClick={() => {
                            setFilters({ ...filters, status: "" });
                          }}
                        >
                          Select Status
                        </button>
                      </li>
                      <li>
                        <button
                          className="dropdown-item rounded-1"
                          onClick={() => {
                            setFilters({ ...filters, status: "Active" });
                          }}
                        >
                          Active
                        </button>
                      </li>
                      <li>
                        <button
                          className="dropdown-item rounded-1"
                          onClick={() => {
                            setFilters({ ...filters, status: "Inactive" });
                          }}
                        >
                          Inactive
                        </button>
                      </li>
                    </ul>
                  </div>
                  {/* <div className="dropdown">
                  <Link
                    to="#"
                    className="dropdown-toggle btn btn-white d-inline-flex align-items-center"
                    data-bs-toggle="dropdown"
                  >
                    Sort By : Last 7 Days
                  </Link>
                  <ul className="dropdown-menu  dropdown-menu-end p-3">
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        Recently Added
                      </Link>
                    </li>
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        Ascending
                      </Link>
                    </li>
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        Desending
                      </Link>
                    </li>
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        Last Month
                      </Link>
                    </li>
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        Last 7 Days
                      </Link>
                    </li>
                  </ul>
                </div> */}
                </div>
              </div>
              <div className="card-body p-0">
                :
                {tableLoading ? (
                  // Loading Animation
                  <div className="d-flex justify-content-center mb-4">
                    <div className="spinner-border" role="status">
                      <span className="sr-only">Loading...</span>
                    </div>
                  </div>
                ) : (
                  <Table
                    dataSource={tempfiltereddata ?? Data} // Use filtered data if available, otherwise fallback to original
                    columns={columns}
                    rowId="id"
                    Selection={true}
                    onChange={(selectedid) => {
                      console.log("Selected IF", selectedid);
                      setdeleteplan(selectedid);
                    }}
                  />
                )}
              </div>
            </div>
          </div>
          <div className="footer d-sm-flex align-items-center justify-content-between border-top bg-white p-3">
            <p className="mb-0">2014 - 2025 © SmartHR.</p>
            <p>
              Designed &amp; Developed By{" "}
              <Link to="amasQIS.ai" className="text-primary">
                amasQIS.ai
              </Link>
            </p>
          </div>
        </div>
        {/* /Page Wrapper */}
        {/* Add Company */}
        <div className="modal fade" id="add_company">
          <div className="modal-dialog modal-dialog-centered modal-lg">
            <div className="modal-content">
              <div className="modal-header">
                <h4 className="modal-title">Add New Company</h4>
                <button
                  type="button"
                  className="btn-close custom-btn-close"
                  data-bs-dismiss="modal"
                  aria-label="Close"
                  onClick={() => {
                    reset_form();
                  }}
                >
                  <i className="ti ti-x" />
                </button>
              </div>
              <form onSubmit={handleSubmit} autoComplete="off">
                <div className="modal-body pb-0">
                  <div className="row">
                    <div className="col-md-12">
                      <div className="d-flex align-items-center flex-wrap row-gap-3 bg-light w-100 rounded p-3 mb-4">
                        <div className="d-flex align-items-center justify-content-center avatar avatar-xxl rounded-circle border border-dashed me-2 flex-shrink-0 text-dark frames">
                          {logo ? (
                            <img
                              src={logo}
                              alt="Uploaded Logo"
                              className="rounded-circle"
                              style={{
                                width: "100%",
                                height: "100%",
                                objectFit: "cover",
                              }}
                            />
                          ) : imageupload ? (
                            <div
                              className="spinner-border text-primary"
                              role="status"
                            >
                              <span className="visually-hidden">
                                Uploading...
                              </span>
                            </div>
                          ) : (
                            <ImageWithBasePath
                              src="assets/img/profiles/avatar-30.jpg"
                              alt="img"
                              className="rounded-circle"
                            />
                          )}
                        </div>
                        <div className="profile-upload">
                          <div className="mb-2">
                            <h6 className="mb-1">Upload Profile Image</h6>
                            <p className="fs-12">Image should be below 4 mb</p>
                          </div>
                          <div className="profile-uploader d-flex align-items-center">
                            <div className="drag-upload-btn btn btn-sm btn-primary me-2">
                              {logo ? "Change" : "Upload"}
                              <input
                                required
                                type="file"
                                className="form-control image-sign"
                                accept=".png,.jpeg,.jpg,.ico"
                                key={inputKey}
                                ref={fileInputRef}
                                onChange={handleImageUpload}
                              />
                            </div>
                            {logo && (
                              <Link
                                to="#"
                                onClick={RemoveLogo}
                                className="btn btn-light btn-sm"
                              >
                                Remove
                              </Link>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3">
                        <label className="form-label">
                          Name <span className="text-danger"> *</span>
                        </label>
                        <input
                          type="text"
                          required
                          className="form-control"
                          name="name"
                          placeholder="Enter company name"
                          value={formData.name}
                          onChange={handleInputChange}
                          maxLength={100}
                        />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3">
                        <label className="form-label">
                          Email Address <span className="text-danger"> *</span>
                        </label>
                        <input
                          type="email"
                          className="form-control"
                          name="email"
                          placeholder="company@example.com"
                          value={formData.email}
                          onChange={handleInputChange}
                          maxLength={100}
                          required
                        />
                      </div>
                    </div>
                    <div className="col-md-12">
                      <div className="mb-3">
                        <label className="form-label">
                          Sub Domain URL<span className="text-danger"> *</span>
                        </label>
                        <div style={{ display: "flex", alignItems: "center" }}>
                          <input
                            type="text"
                            className="form-control"
                            name="domain"
                            placeholder="Subdomain"
                            value={formData.domain}
                            onChange={handleInputChange}
                            maxLength={100}
                            required
                            style={{
                              borderTopRightRadius: 0,
                              borderBottomRightRadius: 0,
                            }}
                          />
                          <span
                            style={{
                              padding: "0 12px",
                              backgroundColor: "#e9ecef",
                              border: "1px solid #ced4da",
                              borderLeft: "none",
                              borderTopRightRadius: "0.25rem",
                              borderBottomRightRadius: "0.25rem",
                              height: "38px",
                              display: "flex",
                              alignItems: "center",
                              fontSize: "1rem",
                              color: "#495057",
                              userSelect: "none",
                            }}
                          >
                            {hostSuffix}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3">
                        <label className="form-label">
                          Phone Number <span className="text-danger"> *</span>
                        </label>
                        <input
                          type="text"
                          className="form-control"
                          name="phone"
                          placeholder="Mobile Number"
                          value={formData.phone}
                          onChange={handleInputChange}
                          maxLength={100}
                          required
                        />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3">
                        <label className="form-label">Website</label>
                        <input
                          type="text"
                          className="form-control"
                          name="website"
                          placeholder="Enter company website"
                          value={formData.website}
                          onChange={handleInputChange}
                          maxLength={100}
                        />
                      </div>
                    </div>
                    {/* <div className="col-md-6">
                    <div className="mb-3 ">
                      <label className="form-label">
                        Password <span className="text-danger"> *</span>
                      </label>
                      <div className="pass-group">
                        <input
                          type={
                            passwordVisibility.password ? "text" : "password"
                          }
                          className="pass-input form-control"
                        />
                        <span
                          className={`ti toggle-passwords ${
                            passwordVisibility.password
                              ? "ti-eye"
                              : "ti-eye-off"
                          }`}
                          onClick={() => togglePasswordVisibility("password")}
                        ></span>
                      </div>
                    </div>
                  </div>
                  <div className="col-md-6">
                    <div className="mb-3 ">
                      <label className="form-label">
                        Confirm Password <span className="text-danger"> *</span>
                      </label>
                      <div className="pass-group">
                        <input
                          type={
                            passwordVisibility.confirmPassword
                              ? "text"
                              : "password"
                          }
                          className="pass-input form-control"
                        />
                        <span
                          className={`ti toggle-passwords ${
                            passwordVisibility.confirmPassword
                              ? "ti-eye"
                              : "ti-eye-off"
                          }`}
                          onClick={() =>
                            togglePasswordVisibility("confirmPassword")
                          }
                        ></span>
                      </div>
                    </div>
                  </div> */}
                    <div className="col-md-12">
                      <div className="mb-3">
                        <label className="form-label">Address</label>
                        <input
                          type="text"
                          className="form-control"
                          name="address"
                          placeholder="Enter company address"
                          value={formData.address}
                          onChange={handleInputChange}
                          maxLength={100}
                        />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3 ">
                        <label className="form-label">
                          Plan Name <span className="text-danger"> *</span>
                        </label>
                        <CommonSelect
                          className="select"
                          options={planName}
                          defaultValue={formData.plan_name}
                          onChange={(selectedOption) =>
                            handleSelectChange("plan_id", selectedOption)
                          }
                        />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3 ">
                        <label className="form-label">
                          Plan Type <span className="text-danger"> *</span>
                        </label>
                        <CommonSelect
                          className="select"
                          options={planType}
                          defaultValue={formData.plan_type}
                          disabled={true}
                        />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3 ">
                        <label className="form-label">
                          Currency <span className="text-danger"> *</span>
                        </label>
                        <CommonSelect
                          className="select"
                          options={currency}
                          defaultValue={formData.currency}
                          disabled={true}
                        />
                      </div>
                    </div>
                    {/* <div className="col-md-4">
                    <div className="mb-3 ">
                      <label className="form-label">
                        Language <span className="text-danger"> *</span>
                      </label>
                      <CommonSelect
                        className="select"
                        options={language}
                        defaultValue={language[0]}
                      />
                    </div>
                  </div> */}
                    <div className="col-md-6">
                      <div className="mb-3 ">
                        <label className="form-label">Status</label>
                        <CommonSelect
                          className="select"
                          key={resetKey}
                          options={statusChoose}
                          defaultValue={formData.status}
                          onChange={(selectedOption) =>
                            handleSelectChange("status", selectedOption)
                          }
                        />
                      </div>
                    </div>
                  </div>
                </div>
                <div className="modal-footer">
                  <button
                    type="button"
                    className="btn btn-light me-2"
                    onClick={reset_form}
                    data-bs-dismiss="modal"
                    id="close-add-company"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    // data-bs-dismiss="modal"
                    className="btn btn-primary"
                    disabled={isLoading} // Disable the button when loading
                  >
                    {isLoading ? (
                      <>
                        <span
                          className="spinner-border spinner-border-sm me-2"
                          role="status"
                          aria-hidden="true"
                        />
                        Adding...
                      </>
                    ) : (
                      "Add Companyss"
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
        {/* /Add Company */}
        {/* Edit Company */}
        <div className="modal fade" id="edit_company">
          {editcompanyloader ? (
            <div className="d-flex justify-content-center align-items-center p-5">
              <div className="spinner-border text-primary" role="status">
                <span className="visually-hidden">Loading...</span>
              </div>
            </div>
          ) : (
            <div className="modal-dialog modal-dialog-centered modal-lg">
              <div className="modal-content">
                <div className="modal-header">
                  <h4 className="modal-title">Edit Company</h4>
                  <button
                    type="button"
                    className="btn-close custom-btn-close"
                    data-bs-dismiss="modal"
                    aria-label="Close"
                    onClick={() => {
                      reset_form();
                    }}
                  >
                    <i className="ti ti-x" />
                  </button>
                </div>
                <form onSubmit={EdithandleSubmit} autoComplete="off">
                  <div className="modal-body pb-0">
                    <div className="row">
                      <div className="col-md-12">
                        <div className="d-flex align-items-center flex-wrap row-gap-3 bg-light w-100 rounded p-3 mb-4">
                          <div className="d-flex align-items-center justify-content-center avatar avatar-xxl rounded-circle border border-dashed me-2 flex-shrink-0 text-dark frames">
                            {logo ? (
                              <img
                                src={logo}
                                alt="Uploaded Logo"
                                className="rounded-circle"
                                style={{
                                  width: "100%",
                                  height: "100%",
                                  objectFit: "cover",
                                }}
                              />
                            ) : imageupload ? (
                              <div
                                className="spinner-border text-primary"
                                role="status"
                              >
                                <span className="visually-hidden">
                                  Uploading...
                                </span>
                              </div>
                            ) : (
                              <ImageWithBasePath
                                src="assets/img/profiles/avatar-30.jpg"
                                alt="img"
                                className="rounded-circle"
                              />
                            )}
                          </div>
                          <div className="profile-upload">
                            <div className="mb-2">
                              <h6 className="mb-1">Upload Profile Image</h6>
                              <p className="fs-12">
                                Image should be below 4 mb
                              </p>
                            </div>
                            <div className="profile-uploader d-flex align-items-center">
                              <div className="drag-upload-btn btn btn-sm btn-primary me-2">
                                {logo ? "Change" : "Upload"}
                                <input
                                  type="file"
                                  className="form-control image-sign"
                                  accept=".png,.jpeg,.jpg,.ico"
                                  key={inputKey}
                                  ref={fileInputRef}
                                  onChange={handleImageUpload}
                                />
                              </div>
                              {logo && (
                                <Link
                                  to="#"
                                  onClick={RemoveLogo}
                                  className="btn btn-light btn-sm"
                                >
                                  Remove
                                </Link>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="col-md-6">
                        <div className="mb-3">
                          <label className="form-label">
                            Name <span className="text-danger"> *</span>
                          </label>
                          <input
                            type="text"
                            required
                            className="form-control"
                            name="name"
                            placeholder="Enter company name"
                            value={formData.name}
                            onChange={handleInputChange}
                            maxLength={100}
                          />
                        </div>
                      </div>
                      <div className="col-md-6">
                        <div className="mb-3">
                          <label className="form-label">
                            Email Address{" "}
                            <span className="text-danger"> *</span>
                          </label>
                          <input
                            type="email"
                            className="form-control"
                            name="email"
                            placeholder="company@example.com"
                            value={formData.email}
                            onChange={handleInputChange}
                            maxLength={100}
                            required
                          />
                        </div>
                      </div>
                      <div className="col-md-12">
                        <div className="mb-3">
                          <label className="form-label">
                            Sub Domain URL
                            <span className="text-danger"> *</span>
                          </label>
                          <div
                            style={{ display: "flex", alignItems: "center" }}
                          >
                            <input
                              type="text"
                              className="form-control"
                              name="domain"
                              placeholder="Subdomain"
                              value={formData.domain}
                              onChange={handleInputChange}
                              maxLength={100}
                              required
                              style={{
                                borderTopRightRadius: 0,
                                borderBottomRightRadius: 0,
                              }}
                            />
                            <span
                              style={{
                                padding: "0 12px",
                                backgroundColor: "#e9ecef",
                                border: "1px solid #ced4da",
                                borderLeft: "none",
                                borderTopRightRadius: "0.25rem",
                                borderBottomRightRadius: "0.25rem",
                                height: "38px",
                                display: "flex",
                                alignItems: "center",
                                fontSize: "1rem",
                                color: "#495057",
                                userSelect: "none",
                              }}
                            >
                              {hostSuffix}
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="col-md-6">
                        <div className="mb-3">
                          <label className="form-label">
                            Phone Number <span className="text-danger"> *</span>
                          </label>
                          <input
                            type="text"
                            className="form-control"
                            name="phone"
                            placeholder="Mobile Number"
                            value={formData.phone}
                            onChange={handleInputChange}
                            maxLength={100}
                            required
                          />
                        </div>
                      </div>
                      <div className="col-md-6">
                        <div className="mb-3">
                          <label className="form-label">Website</label>
                          <input
                            type="text"
                            className="form-control"
                            name="website"
                            placeholder="Enter company website"
                            value={formData.website}
                            onChange={handleInputChange}
                            maxLength={100}
                          />
                        </div>
                      </div>
                      {/* <div className="col-md-6">
                    <div className="mb-3 ">
                      <label className="form-label">
                        Password <span className="text-danger"> *</span>
                      </label>
                      <div className="pass-group">
                        <input
                          type={
                            passwordVisibility.password ? "text" : "password"
                          }
                          className="pass-input form-control"
                        />
                        <span
                          className={`ti toggle-passwords ${
                            passwordVisibility.password
                              ? "ti-eye"
                              : "ti-eye-off"
                          }`}
                          onClick={() => togglePasswordVisibility("password")}
                        ></span>
                      </div>
                    </div>
                  </div>
                  <div className="col-md-6">
                    <div className="mb-3 ">
                      <label className="form-label">
                        Confirm Password <span className="text-danger"> *</span>
                      </label>
                      <div className="pass-group">
                        <input
                          type={
                            passwordVisibility.confirmPassword
                              ? "text"
                              : "password"
                          }
                          className="pass-input form-control"
                        />
                        <span
                          className={`ti toggle-passwords ${
                            passwordVisibility.confirmPassword
                              ? "ti-eye"
                              : "ti-eye-off"
                          }`}
                          onClick={() =>
                            togglePasswordVisibility("confirmPassword")
                          }
                        ></span>
                      </div>
                    </div>
                  </div> */}
                      <div className="col-md-12">
                        <div className="mb-3">
                          <label className="form-label">Address</label>
                          <input
                            type="text"
                            className="form-control"
                            name="address"
                            placeholder="Enter company address"
                            value={formData.address}
                            onChange={handleInputChange}
                            maxLength={100}
                          />
                        </div>
                      </div>
                      <div className="col-md-6">
                        <div className="mb-3 ">
                          <label className="form-label">
                            Plan Name <span className="text-danger"> *</span>
                          </label>
                          <CommonSelect
                            className="select"
                            options={planName}
                            defaultValue={formData.plan_name}
                            onChange={(selectedOption) =>
                              handleSelectChange("plan_id", selectedOption)
                            }
                          />
                        </div>
                      </div>
                      <div className="col-md-6">
                        <div className="mb-3 ">
                          <label className="form-label">
                            Plan Type <span className="text-danger"> *</span>
                          </label>
                          <CommonSelect
                            className="select"
                            options={planType}
                            defaultValue={formData.plan_type}
                            disabled={true}
                          />
                        </div>
                      </div>
                      <div className="col-md-6">
                        <div className="mb-3 ">
                          <label className="form-label">
                            Currency <span className="text-danger"> *</span>
                          </label>
                          <CommonSelect
                            className="select"
                            options={currency}
                            defaultValue={formData.currency}
                            disabled={true}
                          />
                        </div>
                      </div>
                      {/* <div className="col-md-4">
                    <div className="mb-3 ">
                      <label className="form-label">
                        Language <span className="text-danger"> *</span>
                      </label>
                      <CommonSelect
                        className="select"
                        options={language}
                        defaultValue={language[0]}
                      />
                    </div>
                  </div> */}
                      <div className="col-md-6">
                        <div className="mb-3 ">
                          <label className="form-label">Status</label>
                          <CommonSelect
                            className="select"
                            options={statusChoose}
                            defaultValue={formData.status}
                            onChange={(selectedOption) =>
                              handleSelectChange("status", selectedOption)
                            }
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="modal-footer">
                    <button
                      type="button"
                      className="btn btn-light me-2"
                      onClick={reset_form}
                      data-bs-dismiss="modal"
                      id="close-add-company"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      // data-bs-dismiss="modal"
                      className="btn btn-primary"
                      disabled={isLoadingediting} // Disable the button when loading
                    >
                      {isLoadingediting ? (
                        <>
                          <span
                            className="spinner-border spinner-border-sm me-2"
                            role="status"
                            aria-hidden="true"
                          />
                          Editing...
                        </>
                      ) : (
                        "Edit Company"
                      )}
                    </button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
        {/* /Edit Company */}
        {/* Upgrade Information */}
        <div className="modal fade" id="upgrade_info">
          <div className="modal-dialog modal-dialog-centered modal-lg">
            <div className="modal-content">
              <div className="modal-header">
                <h4 className="modal-title">Upgrade Package</h4>
                <button
                  type="button"
                  className="btn-close custom-btn-close"
                  data-bs-dismiss="modal"
                  aria-label="Close"
                >
                  <i className="ti ti-x" />
                </button>
              </div>
              <div className="p-3 mb-1">
                <div className="rounded bg-light p-3">
                  <h5 className="mb-3">Current Plan Details</h5>
                  <div className="row align-items-center">
                    <div className="col-md-4">
                      <div className="mb-3">
                        <p className="fs-12 mb-0">Company Name</p>
                        <p className="text-gray-9">BrightWave Innovations</p>
                      </div>
                    </div>
                    <div className="col-md-4">
                      <div className="mb-3">
                        <p className="fs-12 mb-0">Plan Name</p>
                        <p className="text-gray-9">Advanced</p>
                      </div>
                    </div>
                    <div className="col-md-4">
                      <div className="mb-3">
                        <p className="fs-12 mb-0">Plan Type</p>
                        <p className="text-gray-9">Monthly</p>
                      </div>
                    </div>
                  </div>
                  <div className="row align-items-center">
                    <div className="col-md-4">
                      <div className="mb-3">
                        <p className="fs-12 mb-0">Price</p>
                        <p className="text-gray-9">200</p>
                      </div>
                    </div>
                    <div className="col-md-4">
                      <div className="mb-3">
                        <p className="fs-12 mb-0">Register Date</p>
                        <p className="text-gray-9">12 Sep 2024</p>
                      </div>
                    </div>
                    <div className="col-md-4">
                      <div className="mb-3">
                        <p className="fs-12 mb-0">Expiring On</p>
                        <p className="text-gray-9">11 Oct 2024</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <form action="companies.html">
                <div className="modal-body pb-0">
                  <h5 className="mb-4">Change Plan</h5>
                  <div className="row">
                    <div className="col-md-6">
                      <div className="mb-3 ">
                        <label className="form-label">
                          Plan Name <span className="text-danger">*</span>
                        </label>
                        <CommonSelect
                          className="select"
                          options={planName}
                          defaultValue={formData.plan_name}
                        />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3 ">
                        <label className="form-label">
                          Plan Type <span className="text-danger">*</span>
                        </label>
                        <CommonSelect
                          className="select"
                          options={planType}
                          defaultValue={planType[0]}
                        />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3">
                        <label className="form-label">
                          Ammount<span className="text-danger">*</span>
                        </label>
                        <input type="text" className="form-control" />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3">
                        <label className="form-label">
                          Payment Date <span className="text-danger">*</span>
                        </label>
                        <div className="input-icon-end position-relative">
                          <DatePicker
                            className="form-control datetimepicker"
                            format={{
                              format: "DD-MM-YYYY",
                              type: "mask",
                            }}
                            getPopupContainer={getModalContainer}
                            placeholder="DD-MM-YYYY"
                          />
                          <span className="input-icon-addon">
                            <i className="ti ti-calendar text-gray-7" />
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3">
                        <label className="form-label">
                          Next Payment Date{" "}
                          <span className="text-danger">*</span>
                        </label>
                        <div className="input-icon-end position-relative">
                          <DatePicker
                            className="form-control datetimepicker"
                            format={{
                              format: "DD-MM-YYYY",
                              type: "mask",
                            }}
                            getPopupContainer={getModalContainer}
                            placeholder="DD-MM-YYYY"
                          />
                          <span className="input-icon-addon">
                            <i className="ti ti-calendar text-gray-7" />
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3">
                        <label className="form-label">
                          Expiring On <span className="text-danger">*</span>
                        </label>
                        <div className="input-icon-end position-relative">
                          <DatePicker
                            className="form-control datetimepicker"
                            format={{
                              format: "DD-MM-YYYY",
                              type: "mask",
                            }}
                            getPopupContainer={getModalContainer}
                            placeholder="DD-MM-YYYY"
                          />
                          <span className="input-icon-addon">
                            <i className="ti ti-calendar text-gray-7" />
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="modal-footer">
                  <button
                    type="button"
                    className="btn btn-light me-2"
                    data-bs-dismiss="modal"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    data-bs-dismiss="modal"
                    className="btn btn-primary"
                  >
                    Save Changes
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
        {/* /Upgrade Information */}
        {/* Company Detail */}
        <div className="modal fade" id="company_detail">
          <div className="modal-dialog modal-dialog-centered modal-lg">
            <div className="modal-content">
              {viewcompanyloader ? (
                <div className="d-flex justify-content-center align-items-center p-5">
                  <div className="spinner-border text-primary" role="status">
                    <span className="visually-hidden">Loading...</span>
                  </div>
                </div>
              ) : (
                <>
                  <div className="modal-header">
                    <h4 className="modal-title">Company Detail</h4>
                    <button
                      type="button"
                      className="btn-close custom-btn-close"
                      data-bs-dismiss="modal"
                      aria-label="Close"
                    >
                      <i className="ti ti-x" />
                    </button>
                  </div>
                  <div className="moday-body">
                    <div className="p-3">
                      <div className="d-flex justify-content-between align-items-center rounded bg-light p-3">
                        <div className="file-name-icon d-flex align-items-center">
                          <Link
                            to="#"
                            className="avatar avatar-md border rounded-circle flex-shrink-0 me-2"
                          >
                            <ImageWithBasePath
                              src={companydetail.logo}
                              className="img-fluid"
                              isLink={true}
                              alt="img"
                            />
                          </Link>
                          <div>
                            <p className="text-gray-9 fw-medium mb-0">
                              {companydetail.name}
                            </p>
                            <p>{companydetail.email}</p>
                          </div>
                        </div>
                        <span
                          className={`badge ${
                            companydetail.status === "Active"
                              ? "badge-success"
                              : "badge-danger"
                          }`}
                        >
                          <i className="ti ti-point-filled" />
                          {companydetail.status}
                        </span>
                      </div>
                    </div>
                    <div className="p-3">
                      <p className="text-gray-9 fw-medium">Basic Info</p>
                      <div className="pb-1 border-bottom mb-4">
                        <div className="row align-items-center">
                          <div className="col-md-4">
                            <div className="mb-3">
                              <p className="fs-12 mb-0">Account URL</p>
                              <p className="text-gray-9">
                                {companydetail.domain}
                              </p>
                            </div>
                          </div>
                          <div className="col-md-4">
                            <div className="mb-3">
                              <p className="fs-12 mb-0">Phone Number</p>
                              <p className="text-gray-9">
                                {companydetail.phone}
                              </p>
                            </div>
                          </div>
                          <div className="col-md-4">
                            <div className="mb-3">
                              <p className="fs-12 mb-0">Website</p>
                              <p className="text-gray-9">
                                {companydetail.website}
                              </p>
                            </div>
                          </div>
                        </div>
                        <div className="row align-items-center">
                          <div className="col-md-4">
                            <div className="mb-3">
                              <p className="fs-12 mb-0">Currency</p>
                              <p className="text-gray-9">
                                {companydetail.currency}
                              </p>
                            </div>
                          </div>
                          <div className="col-md-4">
                            <div className="mb-3">
                              <p className="fs-12 mb-0">Address</p>
                              <p className="text-gray-9">
                                {companydetail.address}
                              </p>
                            </div>
                          </div>
                        </div>
                      </div>
                      <p className="text-gray-9 fw-medium">Plan Details</p>
                      <div>
                        <div className="row align-items-center">
                          <div className="col-md-4">
                            <div className="mb-3">
                              <p className="fs-12 mb-0">Plan Name</p>
                              <p className="text-gray-9">
                                {companydetail.plan_name}
                              </p>
                            </div>
                          </div>
                          <div className="col-md-4">
                            <div className="mb-3">
                              <p className="fs-12 mb-0">Plan Type</p>
                              <p className="text-gray-9">
                                {companydetail.plan_type}
                              </p>
                            </div>
                          </div>
                          <div className="col-md-4">
                            <div className="mb-3">
                              <p className="fs-12 mb-0">Price</p>
                              <p className="text-gray-9">
                                {companydetail.price}
                              </p>
                            </div>
                          </div>
                        </div>
                        <div className="row align-items-center">
                          <div className="col-md-4">
                            <div className="mb-3">
                              <p className="fs-12 mb-0">Register Date</p>
                              <p className="text-gray-9">
                                {companydetail.registerdate}
                              </p>
                            </div>
                          </div>
                          <div className="col-md-4">
                            <div className="mb-3">
                              <p className="fs-12 mb-0">Expiring On</p>
                              <p className="text-gray-9">
                                {companydetail.expiredate}
                              </p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>

        <ToastContainer />
        {/* /Company Detail */}
      </SkeletonTheme>
    </>
  );
};

export default Companies;
