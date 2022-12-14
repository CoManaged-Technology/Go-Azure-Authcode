<!-- Improved compatibility of back to top link: See: https://github.com/othneildrew/Best-README-Template/pull/73 -->
<a name="readme-top"></a>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->

<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/OpenMSPSolutions/Go-Azure-AuthCode?style=for-the-badge)

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <!-- <a href="https://github.com/OpenMSPSolutions/Go-Azure-AuthCode">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a> -->

<h3 align="center">Go-Azure-AuthCode</h3>

  <p align="center">
    Azure AzIdentity add-on to allow the authorization code flow with PKCE
    <br />
    <!-- <a href="https://github.com/OpenMSPSolutions/Go-Azure-AuthCode"><strong>Explore the docs »</strong></a>
    <br /> -->
    <br />
    <a href="https://github.com/OpenMSPSolutions/Go-MSGraph-AuthCode-Tutorial">Example</a>
    ·
    <a href="https://github.com/OpenMSPSolutions/Go-Azure-AuthCode/issues">Report Bug</a>
    ·
    <a href="https://github.com/OpenMSPSolutions/Go-Azure-AuthCode/issues">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <!-- <li><a href="#acknowledgments">Acknowledgments</a></li> -->
  </ol>
</details>

<!-- ABOUT THE PROJECT -->
## About The Project

[![Product Name Screen Shot][product-screenshot]](https://example.com)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.

### Prerequisites

This is an example of how to list things you need to use the software and how to install them.

* npm

  ```sh
  npm install npm@latest -g
  ```

### Installation

1. Get a free API Key at [https://example.com](https://example.com)
2. Clone the repo

   ```sh
   git clone https://github.com/OpenMSPSolutions/Go-Azure-AuthCode.git
   ```

3. Install NPM packages

   ```sh
   npm install
   ```

4. Enter your API in `config.js`

   ```js
   const API_KEY = 'ENTER YOUR API';
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- USAGE EXAMPLES -->
## Usage

Use this space to show useful examples of how a project can be used. Additional screenshots, code examples and demos work well in this space. You may also link to more resources.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ROADMAP -->
## Roadmap

* [X] Microsoft oAuth 2.0 Auth link generation
* [X] Auto start/stop http server for receiving authorization codes
* [X] Auto handle token requests from the azidentity auth provider
* [X] PKCE Support
* [ ] Auth Tenant Support
* [ ] Refresh token support
* [ ] ID Token Support
* [ ] Go-SecureRoute (ngrok like proxy system) support to avoid using <http://localhost> for receiving authorization codes

See the [open issues](https://github.com/OpenMSPSolutions/Go-Azure-AuthCode/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ACKNOWLEDGMENTS -->
<!-- ## Acknowledgments

* []()
* []()
* []()

<p align="right">(<a href="#readme-top">back to top</a>)</p> -->

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/CoManaged-Technology/Go-Azure-Authcode?style=for-the-badge
[contributors-url]: https://github.com/CoManaged-Technology/Go-Azure-Authcode/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/CoManaged-Technology/Go-Azure-Authcode?style=for-the-badge
[forks-url]: https://github.com/CoManaged-Technology/Go-Azure-AuthCode/network/members
[stars-shield]: https://img.shields.io/github/stars/CoManaged-Technology/Go-Azure-AuthCode.svg?style=for-the-badge
[stars-url]: https://github.com/CoManaged-Technology/Go-Azure-AuthCode/stargazers
[issues-shield]: https://img.shields.io/github/issues/CoManaged-Technology/Go-Azure-AuthCode.svg?style=for-the-badge
[issues-url]: https://github.com/CoManaged-Technology/Go-Azure-AuthCode/issues
[license-shield]: https://img.shields.io/github/license/CoManaged-Technology/Go-Azure-AuthCode.svg?style=for-the-badge
[license-url]: https://github.com/CoManaged-Technology/Go-Azure-AuthCode/blob/master/LICENSE
