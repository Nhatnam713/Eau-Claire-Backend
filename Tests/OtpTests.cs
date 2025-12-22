using System;
using System.ComponentModel.DataAnnotations;
using FishFarm.BusinessObjects;
using FishFarm.Services;
using FishFarmAPI_v2.Controllers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Moq;

namespace OtpTests
{

    [TestClass]
    public class OtpTests
    {
        public IMemoryCache _cache = null!;
        public IOtpService _otpService = null!;
        public string otp = "";
        public Mock<IUtils> _utils = new Mock<IUtils>();

        [TestInitialize]
        public void Init()
        {
            Environment.SetEnvironmentVariable("SendGrid__SendGridPassword", "abc");

            _cache = new MemoryCache(new MemoryCacheOptions());
            _otpService = new OtpService(_cache, _utils.Object);

        }

        [TestMethod]
        public void SendOTPCode_ReturnOk_WithExistedOTP()
        {
            string email = "phamhoangminhchau1973@gmail.com";
            string device = "device1";
            string cacheKey = $"otp_{device}_{email}";

            _utils.Setup(s => s.GetEmailOtpTemplate(It.IsAny<string>()));

            var result = _otpService.SendOtp("email", device, "", email);

            Assert.IsNotNull(result);
            Assert.AreEqual("200", result.Result.ErrorCode);
            Assert.AreEqual(true, result.Result.IsSuccess);

            Console.WriteLine(_cache.Get<string>(cacheKey));

        }

        [TestMethod]
        public void VerifyOTPCode_Success_Test()
        {
            SendOTPCode_ReturnOk_WithExistedOTP();

            string email = "phamhoangminhchau1973@gmail.com";
            string device = "device1";
            string cacheKey = $"otp_{device}_{email}";

            string otp = _cache.Get<string>(cacheKey)!;
            Console.WriteLine("Nay la:" + otp);

            var result = _otpService.VerifyOtp("email", otp, null, device, null, email, "test-purpose");

            Assert.IsNotNull(result.Data);
            Assert.AreEqual(true, result.IsSuccess);

            Console.WriteLine(result);
        }

        //Controller API

        [TestMethod]
        public async Task SendOTPCode_Controller_ReturnOk_WithExistedOTP()
        {
            var request = new OtpRequest
            {
                Method = "email",
                DeviceId = "device1",
                Email = "test@gmail.com",
                Phone = "",
                Purpose = "login"
            };

            var serviceResult = new ServiceResult
            {
                ErrorCode = "200",
                IsSuccess = true,
                Message = "OTP already exists"
            };

            var otpServiceMock = new Mock<IOtpService>();
            otpServiceMock
                .Setup(s => s.SendOtp("email", "device1", "", "test@gmail.com"))
                .ReturnsAsync(serviceResult);

            var controller = new OtpController(otpServiceMock.Object);

            var result = await controller.GetOtpCode(request);

            var ok = result as OkObjectResult;
            Assert.IsNotNull(ok);

            var payload = ok.Value as ServiceResult;
            Assert.IsNotNull(payload);
            Assert.AreEqual("200", payload.ErrorCode);
        }

        [TestMethod]
        public async Task GetOtpCode_Return500_WhenDeviceIdMissing()
        {
            var request = new OtpRequest
            {
                Method = "email",
                Email = "test@gmail.com"
            };

            var otpServiceMock = new Mock<IOtpService>();
            var controller = new OtpController(otpServiceMock.Object);

            var result = await controller.GetOtpCode(request);

            var status = result as ObjectResult;
            Assert.IsNotNull(status);
            Assert.AreEqual(500, status.StatusCode);
        }

        [TestMethod]
        public async Task GetOtpCode_Return500_WhenServiceError()
        {
            var request = new OtpRequest
            {
                Method = "email",
                DeviceId = "device1",
                Email = "test@gmail.com"
            };

            var serviceResult = new ServiceResult
            {
                ErrorCode = "500",
                Message = "Internal error"
            };

            var otpServiceMock = new Mock<IOtpService>();
            otpServiceMock
                .Setup(s => s.SendOtp(
                    It.IsAny<string>(),
                    It.IsAny<string>(),
                    It.IsAny<string?>(),
                    It.IsAny<string?>()))
                .ReturnsAsync(serviceResult);

            var controller = new OtpController(otpServiceMock.Object);

            var result = await controller.GetOtpCode(request);

            var status = result as ObjectResult;
            Assert.IsNotNull(status);
            Assert.AreEqual(500, status.StatusCode);
        }

        [TestMethod]
        public async Task GetOtpCode_Return400_WhenServiceBadRequest()
        {
            var request = new OtpRequest
            {
                Method = "email",
                DeviceId = "device1",
                Email = "test@gmail.com"
            };

            var serviceResult = new ServiceResult
            {
                ErrorCode = "400",
                Message = "Invalid request"
            };

            var otpServiceMock = new Mock<IOtpService>();
            otpServiceMock
                .Setup(s => s.SendOtp(
                    It.IsAny<string>(),
                    It.IsAny<string>(),
                    It.IsAny<string?>(),
                    It.IsAny<string?>()))
                .ReturnsAsync(serviceResult);

            var controller = new OtpController(otpServiceMock.Object);

            var result = await controller.GetOtpCode(request);

            var badRequest = result as BadRequestObjectResult;
            Assert.IsNotNull(badRequest);
        }

        [TestMethod]
        public void VerifyOTPCode_Controller_ReturnUnauthorized_WhenOtpInvalid()
        {
            var request = new OtpRequest
            {
                Method = "email",
                InputOtp = "123456",
                Purpose = "login",
                Email = "test@gmail.com",
                DeviceId = "device1"
            };

            var verifyResult = new ServiceResult
            {
                IsSuccess = false
            };

            var otpServiceMock = new Mock<IOtpService>();
            otpServiceMock
                .Setup(s => s.VerifyOtp(
                    "email",
                    "123456",
                    It.IsAny<int?>(),
                    "device1",
                    null,
                    "test@gmail.com",
                    "login"))
                .Returns(verifyResult);

            var controller = new OtpController(otpServiceMock.Object);

            var result = controller.VerifyOtpCode(request);

            var unauthorized = result as ObjectResult;
            Assert.IsNotNull(unauthorized);
            Assert.AreEqual(401, unauthorized.StatusCode);
        }

        [TestMethod]
        public void VerifyOTPCode_Return400_WhenRequiredFieldsMissing()
        {
            var request = new OtpRequest
            {
                Method = "",
                InputOtp = "",
                Purpose = ""
            };

            var otpServiceMock = new Mock<IOtpService>();
            var controller = new OtpController(otpServiceMock.Object);

            var result = controller.VerifyOtpCode(request);

            var bad = result as BadRequestObjectResult;
            Assert.IsNotNull(bad);
        }

        [TestMethod]
        public void VerifyOTPCode_Return400_WhenMethodInvalid()
        {
            var request = new OtpRequest
            {
                Method = "push",
                InputOtp = "123456",
                Purpose = "login"
            };

            var otpServiceMock = new Mock<IOtpService>();
            var controller = new OtpController(otpServiceMock.Object);

            var result = controller.VerifyOtpCode(request);

            var bad = result as BadRequestObjectResult;
            Assert.IsNotNull(bad);
        }

        [TestMethod]
        public void VerifyOTPCode_Return400_WhenSmsWithoutPhone()
        {
            var request = new OtpRequest
            {
                Method = "sms",
                InputOtp = "123456",
                Purpose = "login",
                Phone = ""
            };

            var otpServiceMock = new Mock<IOtpService>();
            var controller = new OtpController(otpServiceMock.Object);

            var result = controller.VerifyOtpCode(request);

            var bad = result as BadRequestObjectResult;
            Assert.IsNotNull(bad);
        }

        [TestMethod]
        public void VerifyOTPCode_Return400_WhenEmailWithoutEmail()
        {
            var request = new OtpRequest
            {
                Method = "email",
                InputOtp = "123456",
                Purpose = "login",
                Email = ""
            };

            var otpServiceMock = new Mock<IOtpService>();
            var controller = new OtpController(otpServiceMock.Object);

            var result = controller.VerifyOtpCode(request);

            var bad = result as BadRequestObjectResult;
            Assert.IsNotNull(bad);
        }

        [TestMethod]
        public void VerifyOTPCode_Controller_ReturnOk_WhenSuccess()
        {
            var request = new OtpRequest
            {
                Method = "email",
                InputOtp = "123456",
                Purpose = "login",
                Email = "test@gmail.com",
                DeviceId = "device1"
            };

            var serviceResult = new ServiceResult
            {
                IsSuccess = true,
                Data = new { verified = true }
            };

            var otpServiceMock = new Mock<IOtpService>();
            otpServiceMock
                .Setup(s => s.VerifyOtp(
                    "email",
                    "123456",
                    It.IsAny<int?>(),
                    "device1",
                    null,
                    "test@gmail.com",
                    "login"))
                .Returns(serviceResult);

            var controller = new OtpController(otpServiceMock.Object);

            var result = controller.VerifyOtpCode(request);

            var ok = result as OkObjectResult;
            Assert.IsNotNull(ok);
        }

        [TestMethod]
        public void VerifyOtp_ReturnFail_WhenOtpNotInCache()
        {
            // Arrange
            var cache = new MemoryCache(new MemoryCacheOptions());
            var utilsMock = new Mock<IUtils>();
            var service = new OtpService(cache, utilsMock.Object);

            // Act
            var result = service.VerifyOtp(
                method: "email",
                inputOtp: "123456",
                userId: null,
                deviceId: "device-x",
                phone: null,
                email: "noexist@gmail.com",
                purpose: "login"
            );

            // Assert
            Assert.IsFalse(result.IsSuccess);
            Assert.AreEqual("500", result.ErrorCode);
        }

        [TestMethod]
        public void VerifyOtp_ReturnFail_WhenMethodMismatch()
        {
            var cache = new MemoryCache(new MemoryCacheOptions());
            var utilsMock = new Mock<IUtils>();
            var service = new OtpService(cache, utilsMock.Object);

            cache.Set("otp_device1_test@gmail.com", "654321");

            var result = service.VerifyOtp(
                method: "sms", // khác method
                inputOtp: "654321",
                userId: null,
                deviceId: "device1",
                phone: "0123",
                email: null,
                purpose: "login"
            );

            Assert.IsFalse(result.IsSuccess);
        }

        [TestMethod]
        public async Task SendOtp_ShouldOverwriteExistingOtp()
        {
            var cache = new MemoryCache(new MemoryCacheOptions());
            var utilsMock = new Mock<IUtils>();
            utilsMock.Setup(u => u.GetEmailOtpTemplate(It.IsAny<string>()))
                     .Returns("<html></html>");

            var service = new OtpService(cache, utilsMock.Object);

            string key = "otp_device1_test@gmail.com";
            cache.Set(key, "111111");

            await service.SendOtp("email", "device1", null, "test@gmail.com");

            var newOtp = cache.Get<string>(key);

            Assert.IsNotNull(newOtp);
            Assert.AreNotEqual("111111", newOtp);
        }

        [TestMethod]
        public void VerifyOtp_ShouldStoreCorrectTempTokenData()
        {
            var cache = new MemoryCache(new MemoryCacheOptions());
            var utilsMock = new Mock<IUtils>();
            var service = new OtpService(cache, utilsMock.Object);

            cache.Set("otp_device1_test@gmail.com", "123456");

            var result = service.VerifyOtp(
                "email",
                "123456",
                99,
                "device1",
                null,
                "test@gmail.com",
                "reset-password"
            );

            var token = result.Data!.ToString();
            var tokenData = cache.Get<TempTokenData>(token);

            Assert.IsNotNull(tokenData);
            Assert.AreEqual(99, tokenData.UserId);
            Assert.AreEqual("email", tokenData.Method);
            Assert.AreEqual("reset-password", tokenData.Purpose);
            Assert.IsFalse(tokenData.isVerified);
        }

    }
}
